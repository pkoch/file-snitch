#define FUSE_USE_VERSION 312

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libfuse_shim.h"

struct fsn_virtual_file {
    char *name;
    char *path;
    char *content;
    size_t size;
    size_t capacity;
    mode_t mode;
    uint64_t inode;
};

struct fsn_fuse_session {
    char *mount_path;
    char *backing_store_path;
    char *status_file_name;
    char *status_file_path;
    char *status_file_content;
    struct fsn_virtual_file *user_files;
    uint32_t user_file_count;
    uint32_t user_file_capacity;
    uint64_t next_inode;
    void *daemon_state;
    uint8_t run_in_foreground;
    uint8_t allow_mutations;
    uint32_t configured_operation_count;
    uint32_t planned_argument_count;
    char **planned_arguments;
    struct fuse_operations operations;
};

static char *fsn_strdup(const char *value);
static int fsn_is_root_path(const char *path);
static int fsn_is_status_path(const struct fsn_fuse_session *session, const char *path);
static int fsn_is_user_file_path(const char *path);
static void fsn_fill_root_stat(struct stat *stbuf);
static void fsn_fill_status_stat(const struct fsn_fuse_session *session, struct stat *stbuf);
static void fsn_fill_user_file_stat(const struct fsn_virtual_file *file, struct stat *stbuf);
static int fsn_build_status_file(struct fsn_fuse_session *session);
static int fsn_copy_read_slice(const char *source, char *buf, size_t size, off_t off);
static int fsn_fill_node_info_from_stat(uint32_t kind, const struct stat *stbuf, struct fsn_fuse_node_info *out);
static int fsn_mutations_allowed(const struct fsn_fuse_session *session);
static struct fsn_virtual_file *fsn_find_user_file(struct fsn_fuse_session *session, const char *path);
static const struct fsn_virtual_file *fsn_find_user_file_const(
    const struct fsn_fuse_session *session,
    const char *path
);
static int fsn_ensure_user_file_capacity(struct fsn_fuse_session *session, uint32_t target);
static void fsn_free_virtual_file(struct fsn_virtual_file *file);
static int fsn_create_user_file(struct fsn_fuse_session *session, const char *path, mode_t mode);
static int fsn_write_user_file(
    struct fsn_virtual_file *file,
    const char *buf,
    size_t size,
    off_t off
);
static int fsn_truncate_user_file(struct fsn_virtual_file *file, off_t size);
static int fsn_remove_user_file(struct fsn_fuse_session *session, const char *path);

static void *fsn_fuse_init(struct fuse_conn_info *conn) {
    (void)conn;
    return fuse_get_context()->private_data;
}

static void fsn_fuse_destroy(void *private_data) {
    (void)private_data;
}

static int fsn_fuse_getattr(const char *path, struct stat *stbuf) {
    struct fsn_fuse_session *session;
    const struct fsn_virtual_file *file;

    if (path == NULL || stbuf == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_is_root_path(path)) {
        fsn_fill_root_stat(stbuf);
        return 0;
    }

    if (fsn_is_status_path(session, path)) {
        fsn_fill_status_stat(session, stbuf);
        return 0;
    }

    file = fsn_find_user_file_const(session, path);
    if (file != NULL) {
        fsn_fill_user_file_stat(file, stbuf);
        return 0;
    }

    return -ENOENT;
}

static int fsn_fuse_opendir(const char *path, struct fuse_file_info *fi) {
    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    if (!fsn_is_root_path(path)) {
        return -ENOENT;
    }

    return 0;
}

static int fsn_fuse_readdir(
    const char *path,
    void *buf,
    fuse_fill_dir_t filler,
    off_t off,
    struct fuse_file_info *fi
) {
    struct stat stbuf;

    (void)off;
    (void)fi;

    if (path == NULL || buf == NULL || filler == NULL) {
        return -EINVAL;
    }

    if (!fsn_is_root_path(path)) {
        return -ENOENT;
    }

    memset(&stbuf, 0, sizeof(stbuf));
    fsn_fill_root_stat(&stbuf);
    if (filler(buf, ".", &stbuf, 0) != 0) {
        return 0;
    }

    if (filler(buf, "..", &stbuf, 0) != 0) {
        return 0;
    }

    memset(&stbuf, 0, sizeof(stbuf));
    fsn_fill_status_stat(fuse_get_context()->private_data, &stbuf);
    if (filler(buf, ((struct fsn_fuse_session *)fuse_get_context()->private_data)->status_file_name, &stbuf, 0) != 0) {
        return 0;
    }

    {
        struct fsn_fuse_session *session = fuse_get_context()->private_data;
        uint32_t index;

        for (index = 0; index < session->user_file_count; index += 1) {
            memset(&stbuf, 0, sizeof(stbuf));
            fsn_fill_user_file_stat(&session->user_files[index], &stbuf);
            if (filler(buf, session->user_files[index].name, &stbuf, 0) != 0) {
                return 0;
            }
        }
    }

    return 0;
}

static int fsn_fuse_releasedir(const char *path, struct fuse_file_info *fi) {
    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    if (!fsn_is_root_path(path)) {
        return -ENOENT;
    }

    return 0;
}

static int fsn_is_root_path(const char *path) {
    return path != NULL && strcmp(path, "/") == 0;
}

static int fsn_is_user_file_path(const char *path) {
    const char *tail;

    if (path == NULL || path[0] != '/' || path[1] == '\0') {
        return 0;
    }

    tail = strchr(path + 1, '/');
    return tail == NULL;
}

static int fsn_is_status_path(const struct fsn_fuse_session *session, const char *path) {
    return session != NULL &&
        path != NULL &&
        session->status_file_path != NULL &&
        strcmp(path, session->status_file_path) == 0;
}

static void fsn_fill_root_stat(struct stat *stbuf) {
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    stbuf->st_ino = 1;
}

static void fsn_fill_status_stat(const struct fsn_fuse_session *session, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | 0444;
    stbuf->st_nlink = 1;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = session != NULL && session->status_file_content != NULL ?
        (off_t)strlen(session->status_file_content) : 0;
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    stbuf->st_ino = 2;
}

static void fsn_fill_user_file_stat(const struct fsn_virtual_file *file, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | file->mode;
    stbuf->st_nlink = 1;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = (off_t)file->size;
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    stbuf->st_ino = (ino_t)file->inode;
}

static int fsn_build_status_file(struct fsn_fuse_session *session) {
    const char *name = "file-snitch-status";
    int written;
    size_t content_size;

    session->status_file_name = fsn_strdup(name);
    session->status_file_path = fsn_strdup("/file-snitch-status");
    if (session->status_file_name == NULL || session->status_file_path == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    content_size = strlen(session->mount_path) + strlen(session->backing_store_path) + 256;
    session->status_file_content = calloc(content_size, sizeof(char));
    if (session->status_file_content == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    written = snprintf(
        session->status_file_content,
        content_size,
        "backend=libfuse\nmount_path=%s\nbacking_store=%s\nconfigured_ops=%u\nplanned_args=%u\n",
        session->mount_path,
        session->backing_store_path,
        session->configured_operation_count,
        session->planned_argument_count
    );
    if (written < 0 || (size_t)written >= content_size) {
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    return FSN_FUSE_STATUS_OK;
}

static int fsn_fuse_open(const char *path, struct fuse_file_info *fi) {
    struct fsn_fuse_session *session;

    if (path == NULL || fi == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_is_status_path(session, path)) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY) {
            return -EACCES;
        }

        fi->direct_io = 1;
        fi->keep_cache = 0;
        return 0;
    }

    if (fsn_find_user_file(session, path) == NULL) {
        return -ENOENT;
    }

    fi->direct_io = 1;
    fi->keep_cache = 0;
    return 0;
}

static int fsn_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    int result;

    if (path == NULL || fi == NULL) {
        return -EINVAL;
    }

    result = fsn_create_user_file(session, path, mode);
    if (result != 0) {
        return result;
    }

    fi->direct_io = 1;
    fi->keep_cache = 0;
    return 0;
}

static int fsn_fuse_release(const char *path, struct fuse_file_info *fi) {
    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    if (!fsn_is_status_path(fuse_get_context()->private_data, path)) {
        return -ENOENT;
    }

    return 0;
}

static int fsn_copy_read_slice(const char *source, char *buf, size_t size, off_t off) {
    size_t available;
    size_t length;

    if (source == NULL || buf == NULL) {
        return -EINVAL;
    }

    if (off < 0) {
        return -EINVAL;
    }

    available = strlen(source);
    if ((size_t)off >= available) {
        return 0;
    }

    length = available - (size_t)off;
    if (length > size) {
        length = size;
    }

    memcpy(buf, source + off, length);
    return (int)length;
}

static struct fsn_virtual_file *fsn_find_user_file(struct fsn_fuse_session *session, const char *path) {
    uint32_t index;

    if (session == NULL || path == NULL) {
        return NULL;
    }

    for (index = 0; index < session->user_file_count; index += 1) {
        if (strcmp(session->user_files[index].path, path) == 0) {
            return &session->user_files[index];
        }
    }

    return NULL;
}

static const struct fsn_virtual_file *fsn_find_user_file_const(
    const struct fsn_fuse_session *session,
    const char *path
) {
    return fsn_find_user_file((struct fsn_fuse_session *)session, path);
}

static int fsn_ensure_user_file_capacity(struct fsn_fuse_session *session, uint32_t target) {
    struct fsn_virtual_file *files;
    uint32_t capacity;

    if (target <= session->user_file_capacity) {
        return FSN_FUSE_STATUS_OK;
    }

    capacity = session->user_file_capacity == 0 ? 4 : session->user_file_capacity * 2;
    while (capacity < target) {
        capacity *= 2;
    }

    files = realloc(session->user_files, (size_t)capacity * sizeof(*files));
    if (files == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    memset(files + session->user_file_capacity, 0, (size_t)(capacity - session->user_file_capacity) * sizeof(*files));
    session->user_files = files;
    session->user_file_capacity = capacity;
    return FSN_FUSE_STATUS_OK;
}

static void fsn_free_virtual_file(struct fsn_virtual_file *file) {
    if (file == NULL) {
        return;
    }

    free(file->name);
    free(file->path);
    free(file->content);
    memset(file, 0, sizeof(*file));
}

static int fsn_create_user_file(struct fsn_fuse_session *session, const char *path, mode_t mode) {
    struct fsn_virtual_file *file;
    int result;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    if (!fsn_is_user_file_path(path) || fsn_is_status_path(session, path)) {
        return -EINVAL;
    }

    if (fsn_find_user_file(session, path) != NULL) {
        return -EEXIST;
    }

    result = fsn_ensure_user_file_capacity(session, session->user_file_count + 1);
    if (result != FSN_FUSE_STATUS_OK) {
        return -ENOMEM;
    }

    file = &session->user_files[session->user_file_count];
    file->name = fsn_strdup(path + 1);
    file->path = fsn_strdup(path);
    if (file->name == NULL || file->path == NULL) {
        fsn_free_virtual_file(file);
        return -ENOMEM;
    }

    file->mode = (mode & 0777) == 0 ? 0600 : (mode & 0777);
    file->inode = session->next_inode++;
    session->user_file_count += 1;
    return 0;
}

static int fsn_write_user_file(
    struct fsn_virtual_file *file,
    const char *buf,
    size_t size,
    off_t off
) {
    size_t end;
    char *content;

    if (file == NULL || buf == NULL || off < 0) {
        return -EINVAL;
    }

    end = (size_t)off + size;
    if (end > file->capacity) {
        size_t capacity = file->capacity == 0 ? 64 : file->capacity;

        while (capacity < end) {
            capacity *= 2;
        }

        content = realloc(file->content, capacity);
        if (content == NULL) {
            return -ENOMEM;
        }

        if (capacity > file->capacity) {
            memset(content + file->capacity, 0, capacity - file->capacity);
        }

        file->content = content;
        file->capacity = capacity;
    }

    memcpy(file->content + off, buf, size);
    if (end > file->size) {
        file->size = end;
    }
    return (int)size;
}

static int fsn_truncate_user_file(struct fsn_virtual_file *file, off_t size) {
    char *content;

    if (file == NULL || size < 0) {
        return -EINVAL;
    }

    if ((size_t)size > file->capacity) {
        content = realloc(file->content, (size_t)size);
        if (content == NULL) {
            return -ENOMEM;
        }

        memset(content + file->capacity, 0, (size_t)size - file->capacity);
        file->content = content;
        file->capacity = (size_t)size;
    }

    if ((size_t)size > file->size) {
        memset(file->content + file->size, 0, (size_t)size - file->size);
    }

    file->size = (size_t)size;
    return 0;
}

static int fsn_remove_user_file(struct fsn_fuse_session *session, const char *path) {
    uint32_t index;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    for (index = 0; index < session->user_file_count; index += 1) {
        if (strcmp(session->user_files[index].path, path) == 0) {
            fsn_free_virtual_file(&session->user_files[index]);
            if (index + 1 < session->user_file_count) {
                memmove(
                    &session->user_files[index],
                    &session->user_files[index + 1],
                    (size_t)(session->user_file_count - index - 1) * sizeof(*session->user_files)
                );
            }
            session->user_file_count -= 1;
            memset(&session->user_files[session->user_file_count], 0, sizeof(*session->user_files));
            return 0;
        }
    }

    return -ENOENT;
}

static int fsn_mutations_allowed(const struct fsn_fuse_session *session) {
    return session != NULL && session->allow_mutations != 0;
}

static int fsn_fuse_read(
    const char *path,
    char *buf,
    size_t size,
    off_t off,
    struct fuse_file_info *fi
) {
    struct fsn_fuse_session *session;

    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (!fsn_is_status_path(session, path)) {
        const struct fsn_virtual_file *file = fsn_find_user_file_const(session, path);
        if (file == NULL) {
            return -ENOENT;
        }

        return fsn_copy_read_slice(file->content != NULL ? file->content : "", buf, size, off);
    }

    return fsn_copy_read_slice(session->status_file_content, buf, size, off);
}

static int fsn_fuse_write(
    const char *path,
    const char *buf,
    size_t size,
    off_t off,
    struct fuse_file_info *fi
) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    struct fsn_virtual_file *file;

    (void)fi;

    if (path == NULL || buf == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        return -ENOENT;
    }

    return fsn_write_user_file(file, buf, size, off);
}

static int fsn_fuse_truncate(const char *path, off_t size) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    struct fsn_virtual_file *file;

    if (path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        return -ENOENT;
    }

    return fsn_truncate_user_file(file, size);
}

static int fsn_fuse_unlink(const char *path) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;

    if (path == NULL) {
        return -EINVAL;
    }

    if (fsn_is_status_path(session, path)) {
        return -EACCES;
    }

    return fsn_remove_user_file(session, path);
}

static void fsn_fuse_configure_operations(struct fsn_fuse_session *session) {
    memset(&session->operations, 0, sizeof(session->operations));
    session->operations.init = fsn_fuse_init;
    session->operations.destroy = fsn_fuse_destroy;
    session->operations.getattr = fsn_fuse_getattr;
    session->operations.opendir = fsn_fuse_opendir;
    session->operations.readdir = fsn_fuse_readdir;
    session->operations.releasedir = fsn_fuse_releasedir;
    session->operations.create = fsn_fuse_create;
    session->operations.unlink = fsn_fuse_unlink;
    session->operations.open = fsn_fuse_open;
    session->operations.release = fsn_fuse_release;
    session->operations.read = fsn_fuse_read;
    session->operations.write = fsn_fuse_write;
    session->operations.truncate = fsn_fuse_truncate;
    session->configured_operation_count = 12;
}

static void fsn_free_planned_arguments(struct fsn_fuse_session *session) {
    uint32_t index;

    if (session == NULL || session->planned_arguments == NULL) {
        return;
    }

    for (index = 0; index < session->planned_argument_count; index += 1) {
        free(session->planned_arguments[index]);
    }

    free(session->planned_arguments);
    session->planned_arguments = NULL;
    session->planned_argument_count = 0;
}

static int fsn_push_argument(struct fsn_fuse_session *session, const char *value) {
    char **arguments;
    char *copy;
    size_t new_length;

    copy = fsn_strdup(value);
    if (copy == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    new_length = (size_t)session->planned_argument_count + 1;
    arguments = realloc(session->planned_arguments, new_length * sizeof(*arguments));
    if (arguments == NULL) {
        free(copy);
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    session->planned_arguments = arguments;
    session->planned_arguments[session->planned_argument_count] = copy;
    session->planned_argument_count += 1;
    return FSN_FUSE_STATUS_OK;
}

static int fsn_build_execution_plan(struct fsn_fuse_session *session) {
    int status;

    status = fsn_push_argument(session, "file-snitch");
    if (status != FSN_FUSE_STATUS_OK) {
        return status;
    }

    if (session->run_in_foreground) {
        status = fsn_push_argument(session, "-f");
        if (status != FSN_FUSE_STATUS_OK) {
            return status;
        }
    }

    status = fsn_push_argument(session, session->mount_path);
    if (status != FSN_FUSE_STATUS_OK) {
        return status;
    }

    return FSN_FUSE_STATUS_OK;
}

static char **fsn_duplicate_argument_vector(const struct fsn_fuse_session *session) {
    char **argv;
    uint32_t index;

    if (session->planned_argument_count == 0) {
        return NULL;
    }

    argv = calloc((size_t)session->planned_argument_count, sizeof(*argv));
    if (argv == NULL) {
        return NULL;
    }

    for (index = 0; index < session->planned_argument_count; index += 1) {
        argv[index] = fsn_strdup(session->planned_arguments[index]);
        if (argv[index] == NULL) {
            uint32_t cleanup_index;

            for (cleanup_index = 0; cleanup_index < index; cleanup_index += 1) {
                free(argv[cleanup_index]);
            }
            free(argv);
            return NULL;
        }
    }

    return argv;
}

static void fsn_free_argument_vector(char **argv, uint32_t argc) {
    uint32_t index;

    if (argv == NULL) {
        return;
    }

    for (index = 0; index < argc; index += 1) {
        free(argv[index]);
    }

    free(argv);
}

static char *fsn_strdup(const char *value) {
    size_t length;
    char *copy;

    if (value == NULL) {
        return NULL;
    }

    length = strlen(value) + 1;
    copy = malloc(length);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, value, length);
    return copy;
}

int fsn_fuse_probe(struct fsn_fuse_environment *out) {
    if (out == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));
    out->fuse_major_version = FUSE_MAJOR_VERSION;
    out->fuse_minor_version = FUSE_MINOR_VERSION;
    out->high_level_ops_size = sizeof(struct fuse_operations);
    out->uses_c_shim = 1;
    return 0;
}

const char *fsn_fuse_backend_name(void) {
    return "libfuse high-level API";
}

int fsn_fuse_session_create(
    const struct fsn_fuse_session_config *config,
    struct fsn_fuse_session **out
) {
    struct fsn_fuse_session *session;

    if (config == NULL || out == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (config->mount_path == NULL || config->backing_store_path == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (config->mount_path[0] == '\0' || config->backing_store_path[0] == '\0') {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    session->mount_path = fsn_strdup(config->mount_path);
    session->backing_store_path = fsn_strdup(config->backing_store_path);
    if (session->mount_path == NULL || session->backing_store_path == NULL) {
        fsn_fuse_session_destroy(session);
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    session->daemon_state = config->daemon_state;
    session->run_in_foreground = config->run_in_foreground != 0 ? 1 : 0;
    session->allow_mutations = config->allow_mutations != 0 ? 1 : 0;
    session->next_inode = 3;
    fsn_fuse_configure_operations(session);
    if (fsn_build_execution_plan(session) != FSN_FUSE_STATUS_OK) {
        fsn_fuse_session_destroy(session);
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }
    if (fsn_build_status_file(session) != FSN_FUSE_STATUS_OK) {
        fsn_fuse_session_destroy(session);
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    *out = session;
    return FSN_FUSE_STATUS_OK;
}

void fsn_fuse_session_destroy(struct fsn_fuse_session *session) {
    if (session == NULL) {
        return;
    }

    free(session->mount_path);
    free(session->backing_store_path);
    free(session->status_file_name);
    free(session->status_file_path);
    free(session->status_file_content);
    if (session->user_files != NULL) {
        uint32_t index;

        for (index = 0; index < session->user_file_count; index += 1) {
            fsn_free_virtual_file(&session->user_files[index]);
        }
    }
    free(session->user_files);
    fsn_free_planned_arguments(session);
    free(session);
}

int fsn_fuse_session_describe(
    const struct fsn_fuse_session *session,
    struct fsn_fuse_session_info *out
) {
    if (session == NULL || out == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));
    out->high_level_ops_size = sizeof(session->operations);
    out->configured_operation_count = session->configured_operation_count;
    out->planned_argument_count = session->planned_argument_count;
    out->mount_implemented = 0;
    out->has_session_state = 1;
    out->has_daemon_state = session->daemon_state != NULL ? 1 : 0;
    out->has_init_callback = session->operations.init != NULL ? 1 : 0;
    out->run_in_foreground = session->run_in_foreground;
    out->allow_mutations = session->allow_mutations;
    return FSN_FUSE_STATUS_OK;
}

int fsn_fuse_session_run(struct fsn_fuse_session *session) {
    char **argv;
    char *mountpoint;
    int multithreaded;
    struct fuse *fuse;
    int loop_result;

    if (session == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    argv = fsn_duplicate_argument_vector(session);
    if (argv == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    mountpoint = NULL;
    multithreaded = 0;
    fuse = fuse_setup(
        (int)session->planned_argument_count,
        argv,
        &session->operations,
        sizeof(session->operations),
        &mountpoint,
        &multithreaded,
        session->daemon_state
    );
    fsn_free_argument_vector(argv, session->planned_argument_count);

    if (fuse == NULL) {
        return FSN_FUSE_STATUS_SETUP_FAILED;
    }

    loop_result = multithreaded ? fuse_loop_mt(fuse) : fuse_loop(fuse);
    fuse_teardown(fuse, mountpoint);
    if (loop_result != 0) {
        return FSN_FUSE_STATUS_LOOP_FAILED;
    }

    return FSN_FUSE_STATUS_OK;
}

int fsn_fuse_debug_getattr(
    const struct fsn_fuse_session *session,
    const char *path,
    struct fsn_fuse_node_info *out
) {
    struct stat stbuf;
    const struct fsn_virtual_file *file;

    if (session == NULL || path == NULL || out == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    memset(&stbuf, 0, sizeof(stbuf));
    if (fsn_is_root_path(path)) {
        fsn_fill_root_stat(&stbuf);
        return fsn_fill_node_info_from_stat(FSN_FUSE_NODE_DIRECTORY, &stbuf, out);
    }

    if (fsn_is_status_path(session, path)) {
        fsn_fill_status_stat(session, &stbuf);
        return fsn_fill_node_info_from_stat(FSN_FUSE_NODE_REGULAR_FILE, &stbuf, out);
    }

    file = fsn_find_user_file_const(session, path);
    if (file != NULL) {
        fsn_fill_user_file_stat(file, &stbuf);
        return fsn_fill_node_info_from_stat(FSN_FUSE_NODE_REGULAR_FILE, &stbuf, out);
    }

    memset(out, 0, sizeof(*out));
    out->kind = FSN_FUSE_NODE_MISSING;
    return FSN_FUSE_STATUS_OK;
}

uint32_t fsn_fuse_debug_root_entry_count(const struct fsn_fuse_session *session) {
    if (session == NULL || session->status_file_name == NULL) {
        return 0;
    }

    return 1 + session->user_file_count;
}

const char *fsn_fuse_debug_root_entry_at(const struct fsn_fuse_session *session, uint32_t index) {
    if (session == NULL || session->status_file_name == NULL) {
        return NULL;
    }

    if (index == 0) {
        return session->status_file_name;
    }

    index -= 1;
    if (index >= session->user_file_count) {
        return NULL;
    }

    return session->user_files[index].name;
}

int fsn_fuse_debug_read(
    const struct fsn_fuse_session *session,
    const char *path,
    uint64_t offset,
    size_t size,
    char *buf
) {
    if (session == NULL || path == NULL || buf == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (fsn_is_status_path(session, path)) {
        if (offset > (uint64_t)LLONG_MAX) {
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        return fsn_copy_read_slice(session->status_file_content, buf, size, (off_t)offset);
    }

    {
        const struct fsn_virtual_file *file = fsn_find_user_file_const(session, path);
        if (file == NULL) {
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        if (offset > (uint64_t)LLONG_MAX) {
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        return fsn_copy_read_slice(file->content != NULL ? file->content : "", buf, size, (off_t)offset);
    }
}

int fsn_fuse_debug_create_file(struct fsn_fuse_session *session, const char *path, uint32_t mode) {
    if (session == NULL || path == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    return fsn_create_user_file(session, path, (mode_t)mode);
}

int fsn_fuse_debug_write_file(
    struct fsn_fuse_session *session,
    const char *path,
    uint64_t offset,
    size_t size,
    const char *buf
) {
    struct fsn_virtual_file *file;

    if (session == NULL || path == NULL || buf == NULL || offset > (uint64_t)LLONG_MAX) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (!fsn_mutations_allowed(session)) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    return fsn_write_user_file(file, buf, size, (off_t)offset);
}

int fsn_fuse_debug_truncate_file(struct fsn_fuse_session *session, const char *path, uint64_t size) {
    struct fsn_virtual_file *file;

    if (session == NULL || path == NULL || size > (uint64_t)LLONG_MAX) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (!fsn_mutations_allowed(session)) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    return fsn_truncate_user_file(file, (off_t)size);
}

int fsn_fuse_debug_remove_file(struct fsn_fuse_session *session, const char *path) {
    if (session == NULL || path == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    return fsn_remove_user_file(session, path);
}

uint32_t fsn_fuse_session_argument_count(const struct fsn_fuse_session *session) {
    if (session == NULL) {
        return 0;
    }

    return session->planned_argument_count;
}

const char *fsn_fuse_session_argument_at(const struct fsn_fuse_session *session, uint32_t index) {
    if (session == NULL || index >= session->planned_argument_count) {
        return NULL;
    }

    return session->planned_arguments[index];
}

const char *fsn_fuse_session_mount_path(const struct fsn_fuse_session *session) {
    if (session == NULL) {
        return NULL;
    }

    return session->mount_path;
}

const char *fsn_fuse_session_backing_store_path(const struct fsn_fuse_session *session) {
    if (session == NULL) {
        return NULL;
    }

    return session->backing_store_path;
}

const char *fsn_fuse_status_label(int status) {
    switch (status) {
        case FSN_FUSE_STATUS_OK:
            return "ok";
        case FSN_FUSE_STATUS_INVALID_ARGUMENT:
            return "invalid_argument";
        case FSN_FUSE_STATUS_OUT_OF_MEMORY:
            return "out_of_memory";
        case FSN_FUSE_STATUS_NOT_IMPLEMENTED:
            return "not_implemented";
        case FSN_FUSE_STATUS_PLAN_BUILD_FAILED:
            return "plan_build_failed";
        case FSN_FUSE_STATUS_SETUP_FAILED:
            return "setup_failed";
        case FSN_FUSE_STATUS_LOOP_FAILED:
            return "loop_failed";
        default:
            return "unknown_status";
    }
}

static int fsn_fill_node_info_from_stat(uint32_t kind, const struct stat *stbuf, struct fsn_fuse_node_info *out) {
    if (stbuf == NULL || out == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));
    out->kind = kind;
    out->mode = (uint32_t)stbuf->st_mode;
    out->size = (uint64_t)stbuf->st_size;
    out->inode = (uint64_t)stbuf->st_ino;
    return FSN_FUSE_STATUS_OK;
}
