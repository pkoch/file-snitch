#define FUSE_USE_VERSION 312

#include <dirent.h>
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

enum {
    FSN_ROOT_INODE = 1,
    FSN_STATUS_INODE = 2,
    FSN_AUDIT_INODE = 3,
    FSN_FIRST_DYNAMIC_INODE = 16,
};

struct fsn_virtual_file {
    char *name;
    char *path;
    char *content;
    size_t size;
    size_t capacity;
    mode_t mode;
    uint64_t inode;
};

struct fsn_audit_event {
    char *action;
    char *path;
    int32_t result;
};

struct fsn_fuse_session {
    char *mount_path;
    char *backing_store_path;
    char *status_file_name;
    char *status_file_path;
    char *status_file_content;
    char *audit_file_name;
    char *audit_file_path;
    struct fsn_virtual_file *user_files;
    uint32_t user_file_count;
    uint32_t user_file_capacity;
    struct fsn_audit_event *audit_events;
    uint32_t audit_event_count;
    uint32_t audit_event_capacity;
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
static int fsn_is_reserved_name(const char *name);
static int fsn_is_status_path(const struct fsn_fuse_session *session, const char *path);
static int fsn_is_audit_path(const struct fsn_fuse_session *session, const char *path);
static int fsn_is_reserved_path(const struct fsn_fuse_session *session, const char *path);
static int fsn_is_user_file_path(const char *path);
static void fsn_fill_root_stat(struct stat *stbuf);
static void fsn_fill_status_stat(const struct fsn_fuse_session *session, struct stat *stbuf);
static void fsn_fill_audit_stat(const struct fsn_fuse_session *session, struct stat *stbuf);
static void fsn_fill_user_file_stat(const struct fsn_virtual_file *file, struct stat *stbuf);
static int fsn_build_status_file(struct fsn_fuse_session *session);
static char *fsn_render_status_content(const struct fsn_fuse_session *session);
static int fsn_build_audit_file(struct fsn_fuse_session *session);
static char *fsn_render_audit_content(const struct fsn_fuse_session *session);
static int fsn_copy_buffer_slice(const char *source, size_t available, char *buf, size_t size, off_t off);
static int fsn_copy_read_slice(const char *source, char *buf, size_t size, off_t off);
static int fsn_ensure_backing_store_directory(const char *path);
static int fsn_build_backing_store_file_path(
    const struct fsn_fuse_session *session,
    const char *path,
    char *buf,
    size_t buf_size
);
static int fsn_load_backing_store_files(struct fsn_fuse_session *session);
static int fsn_import_backing_store_file(
    struct fsn_fuse_session *session,
    const char *name,
    const char *host_path,
    mode_t mode,
    off_t size
);
static int fsn_fill_node_info_from_stat(uint32_t kind, const struct stat *stbuf, struct fsn_fuse_node_info *out);
static int fsn_mutations_allowed(const struct fsn_fuse_session *session);
static int fsn_ensure_audit_capacity(struct fsn_fuse_session *session, uint32_t target);
static void fsn_free_audit_event(struct fsn_audit_event *event);
static void fsn_record_audit_event(struct fsn_fuse_session *session, const char *action, const char *path, int32_t result);
static struct fsn_virtual_file *fsn_find_user_file(struct fsn_fuse_session *session, const char *path);
static const struct fsn_virtual_file *fsn_find_user_file_const(
    const struct fsn_fuse_session *session,
    const char *path
);
static int fsn_ensure_user_file_capacity(struct fsn_fuse_session *session, uint32_t target);
static void fsn_free_virtual_file(struct fsn_virtual_file *file);
static int fsn_sync_user_file_to_backing_store(
    const struct fsn_fuse_session *session,
    const struct fsn_virtual_file *file
);
static int fsn_snapshot_user_file(
    const struct fsn_virtual_file *file,
    char **out_content,
    size_t *out_size
);
static void fsn_restore_user_file(struct fsn_virtual_file *file, char *content, size_t size);
static int fsn_append_user_file(
    struct fsn_fuse_session *session,
    const char *path,
    mode_t mode,
    struct fsn_virtual_file **out_file
);
static int fsn_create_user_file(struct fsn_fuse_session *session, const char *path, mode_t mode);
static int fsn_persist_created_user_file(struct fsn_fuse_session *session, const char *path, mode_t mode);
static int fsn_write_user_file(
    struct fsn_virtual_file *file,
    const char *buf,
    size_t size,
    off_t off
);
static int fsn_write_user_file_with_persistence(
    const struct fsn_fuse_session *session,
    struct fsn_virtual_file *file,
    const char *buf,
    size_t size,
    off_t off
);
static int fsn_truncate_user_file(struct fsn_virtual_file *file, off_t size);
static int fsn_truncate_user_file_with_persistence(
    const struct fsn_fuse_session *session,
    struct fsn_virtual_file *file,
    off_t size
);
static int fsn_change_user_file_mode_with_persistence(
    const struct fsn_fuse_session *session,
    const char *path,
    mode_t mode
);
static int fsn_sync_path(const struct fsn_fuse_session *session, const char *path);
static int fsn_remove_user_file(struct fsn_fuse_session *session, const char *path);
static int fsn_remove_user_file_with_persistence(struct fsn_fuse_session *session, const char *path);
static int fsn_rename_user_file_with_persistence(
    struct fsn_fuse_session *session,
    const char *from,
    const char *to
);

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

    if (fsn_is_audit_path(session, path)) {
        fsn_fill_audit_stat(session, stbuf);
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

    memset(&stbuf, 0, sizeof(stbuf));
    fsn_fill_audit_stat(fuse_get_context()->private_data, &stbuf);
    if (filler(buf, ((struct fsn_fuse_session *)fuse_get_context()->private_data)->audit_file_name, &stbuf, 0) != 0) {
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

static int fsn_is_reserved_name(const char *name) {
    return name != NULL &&
        (strcmp(name, "file-snitch-status") == 0 || strcmp(name, "file-snitch-audit") == 0);
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

static int fsn_is_audit_path(const struct fsn_fuse_session *session, const char *path) {
    return session != NULL &&
        path != NULL &&
        session->audit_file_path != NULL &&
        strcmp(path, session->audit_file_path) == 0;
}

static int fsn_is_reserved_path(const struct fsn_fuse_session *session, const char *path) {
    return fsn_is_status_path(session, path) || fsn_is_audit_path(session, path);
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
    stbuf->st_ino = FSN_ROOT_INODE;
}

static void fsn_fill_status_stat(const struct fsn_fuse_session *session, struct stat *stbuf) {
    char *content = fsn_render_status_content(session);

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | 0444;
    stbuf->st_nlink = 1;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = content != NULL ? (off_t)strlen(content) : 0;
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    stbuf->st_ino = FSN_STATUS_INODE;
    free(content);
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

static void fsn_fill_audit_stat(const struct fsn_fuse_session *session, struct stat *stbuf) {
    char *content = fsn_render_audit_content(session);

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = S_IFREG | 0444;
    stbuf->st_nlink = 1;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_size = content != NULL ? (off_t)strlen(content) : 0;
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    stbuf->st_ino = FSN_AUDIT_INODE;
    free(content);
}

static int fsn_build_status_file(struct fsn_fuse_session *session) {
    const char *name = "file-snitch-status";

    free(session->status_file_name);
    free(session->status_file_path);
    free(session->status_file_content);
    session->status_file_name = NULL;
    session->status_file_path = NULL;
    session->status_file_content = NULL;

    session->status_file_name = fsn_strdup(name);
    session->status_file_path = fsn_strdup("/file-snitch-status");
    if (session->status_file_name == NULL || session->status_file_path == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    session->status_file_content = fsn_render_status_content(session);
    if (session->status_file_content == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    return FSN_FUSE_STATUS_OK;
}

static char *fsn_render_status_content(const struct fsn_fuse_session *session) {
    char *content;
    int written;
    size_t content_size;

    if (session == NULL) {
        return NULL;
    }

    content_size = strlen(session->mount_path) + strlen(session->backing_store_path) + 320;
    content = calloc(content_size, sizeof(char));
    if (content == NULL) {
        return NULL;
    }

    written = snprintf(
        content,
        content_size,
        "backend=libfuse\nmount_path=%s\nbacking_store=%s\nconfigured_ops=%u\nplanned_args=%u\nbacking_files=%u\n",
        session->mount_path,
        session->backing_store_path,
        session->configured_operation_count,
        session->planned_argument_count,
        session->user_file_count
    );
    if (written < 0 || (size_t)written >= content_size) {
        free(content);
        return NULL;
    }

    return content;
}

static int fsn_build_audit_file(struct fsn_fuse_session *session) {
    session->audit_file_name = fsn_strdup("file-snitch-audit");
    session->audit_file_path = fsn_strdup("/file-snitch-audit");
    if (session->audit_file_name == NULL || session->audit_file_path == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    return FSN_FUSE_STATUS_OK;
}

static char *fsn_render_audit_content(const struct fsn_fuse_session *session) {
    size_t capacity;
    size_t used;
    uint32_t index;
    char *buffer;
    int written;

    if (session == NULL) {
        return NULL;
    }

    capacity = 128 + ((size_t)session->audit_event_count * 128);
    buffer = calloc(capacity, sizeof(char));
    if (buffer == NULL) {
        return NULL;
    }

    if (session->audit_event_count == 0) {
        written = snprintf(buffer, capacity, "[]\n");
        if (written < 0 || (size_t)written >= capacity) {
            free(buffer);
            return NULL;
        }
        return buffer;
    }

    used = 0;
    for (index = 0; index < session->audit_event_count; index += 1) {
        written = snprintf(
            buffer + used,
            capacity - used,
            "{\"action\":\"%s\",\"path\":\"%s\",\"result\":%d}\n",
            session->audit_events[index].action,
            session->audit_events[index].path,
            session->audit_events[index].result
        );
        if (written < 0 || (size_t)written >= capacity - used) {
            free(buffer);
            return NULL;
        }
        used += (size_t)written;
    }

    return buffer;
}

static int fsn_fuse_open(const char *path, struct fuse_file_info *fi) {
    struct fsn_fuse_session *session;

    if (path == NULL || fi == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_is_status_path(session, path) || fsn_is_audit_path(session, path)) {
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

    result = fsn_persist_created_user_file(session, path, mode);
    fsn_record_audit_event(session, "create", path, result);
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

    if (!fsn_is_reserved_path(fuse_get_context()->private_data, path) &&
        fsn_find_user_file(fuse_get_context()->private_data, path) == NULL) {
        return -ENOENT;
    }

    return 0;
}

static int fsn_copy_buffer_slice(const char *source, size_t available, char *buf, size_t size, off_t off) {
    size_t length;

    if (source == NULL || buf == NULL) {
        return -EINVAL;
    }

    if (off < 0) {
        return -EINVAL;
    }

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

static int fsn_copy_read_slice(const char *source, char *buf, size_t size, off_t off) {
    return fsn_copy_buffer_slice(source, source != NULL ? strlen(source) : 0, buf, size, off);
}

static int fsn_ensure_backing_store_directory(const char *path) {
    struct stat stbuf;

    if (path == NULL || path[0] == '\0') {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (stat(path, &stbuf) == 0) {
        return S_ISDIR(stbuf.st_mode) ? FSN_FUSE_STATUS_OK : FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    if (errno != ENOENT) {
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    if (mkdir(path, 0700) != 0) {
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    return FSN_FUSE_STATUS_OK;
}

static int fsn_build_backing_store_file_path(
    const struct fsn_fuse_session *session,
    const char *path,
    char *buf,
    size_t buf_size
) {
    int written;

    if (session == NULL || path == NULL || buf == NULL || buf_size == 0 || !fsn_is_user_file_path(path)) {
        return -EINVAL;
    }

    written = snprintf(buf, buf_size, "%s/%s", session->backing_store_path, path + 1);
    if (written < 0 || (size_t)written >= buf_size) {
        return -ENAMETOOLONG;
    }

    return 0;
}

static int fsn_load_backing_store_files(struct fsn_fuse_session *session) {
    DIR *directory;
    struct dirent *entry;

    if (session == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (fsn_ensure_backing_store_directory(session->backing_store_path) != FSN_FUSE_STATUS_OK) {
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    directory = opendir(session->backing_store_path);
    if (directory == NULL) {
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }

    while ((entry = readdir(directory)) != NULL) {
        char host_path[PATH_MAX];
        struct stat stbuf;
        int written;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (fsn_is_reserved_name(entry->d_name)) {
            continue;
        }

        written = snprintf(host_path, sizeof(host_path), "%s/%s", session->backing_store_path, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(host_path)) {
            closedir(directory);
            return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
        }

        if (stat(host_path, &stbuf) != 0) {
            closedir(directory);
            return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
        }

        if (!S_ISREG(stbuf.st_mode)) {
            continue;
        }

        if (fsn_import_backing_store_file(session, entry->d_name, host_path, stbuf.st_mode, stbuf.st_size) != 0) {
            closedir(directory);
            return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
        }
    }

    closedir(directory);
    return FSN_FUSE_STATUS_OK;
}

static int fsn_import_backing_store_file(
    struct fsn_fuse_session *session,
    const char *name,
    const char *host_path,
    mode_t mode,
    off_t size
) {
    char virtual_path[PATH_MAX];
    struct fsn_virtual_file *file;
    FILE *stream;
    int written;

    if (session == NULL || name == NULL || host_path == NULL || size < 0) {
        return -EINVAL;
    }

    written = snprintf(virtual_path, sizeof(virtual_path), "/%s", name);
    if (written < 0 || (size_t)written >= sizeof(virtual_path)) {
        return -ENAMETOOLONG;
    }

    if (fsn_append_user_file(session, virtual_path, mode, &file) != 0) {
        return -EINVAL;
    }

    if (size == 0) {
        return 0;
    }

    file->content = calloc((size_t)size + 1, sizeof(char));
    if (file->content == NULL) {
        session->user_file_count -= 1;
        memset(file, 0, sizeof(*file));
        return -ENOMEM;
    }

    stream = fopen(host_path, "rb");
    if (stream == NULL) {
        fsn_free_virtual_file(file);
        session->user_file_count -= 1;
        return -errno;
    }

    if (fread(file->content, 1, (size_t)size, stream) != (size_t)size) {
        int read_error = ferror(stream) != 0 ? errno : EIO;

        fclose(stream);
        fsn_free_virtual_file(file);
        session->user_file_count -= 1;
        return -read_error;
    }

    if (fclose(stream) != 0) {
        fsn_free_virtual_file(file);
        session->user_file_count -= 1;
        return -errno;
    }

    file->size = (size_t)size;
    file->capacity = (size_t)size + 1;
    return 0;
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

static int fsn_sync_user_file_to_backing_store(
    const struct fsn_fuse_session *session,
    const struct fsn_virtual_file *file
) {
    char host_path[PATH_MAX];
    FILE *stream;

    if (session == NULL || file == NULL || file->path == NULL) {
        return -EINVAL;
    }

    if (file->size > 0 && file->content == NULL) {
        return -EINVAL;
    }

    if (fsn_build_backing_store_file_path(session, file->path, host_path, sizeof(host_path)) != 0) {
        return -ENAMETOOLONG;
    }

    stream = fopen(host_path, "wb");
    if (stream == NULL) {
        return -errno;
    }

    if (file->size > 0 && fwrite(file->content, 1, file->size, stream) != file->size) {
        int write_error = ferror(stream) != 0 ? errno : EIO;

        fclose(stream);
        return -write_error;
    }

    if (fclose(stream) != 0) {
        return -errno;
    }

    if (chmod(host_path, file->mode) != 0) {
        return -errno;
    }

    return 0;
}

static int fsn_snapshot_user_file(
    const struct fsn_virtual_file *file,
    char **out_content,
    size_t *out_size
) {
    char *copy;

    if (file == NULL || out_content == NULL || out_size == NULL) {
        return -EINVAL;
    }

    *out_content = NULL;
    *out_size = file->size;
    if (file->size == 0) {
        return 0;
    }

    if (file->content == NULL) {
        return -EINVAL;
    }

    copy = malloc(file->size);
    if (copy == NULL) {
        return -ENOMEM;
    }

    memcpy(copy, file->content, file->size);
    *out_content = copy;
    return 0;
}

static void fsn_restore_user_file(struct fsn_virtual_file *file, char *content, size_t size) {
    if (file == NULL) {
        free(content);
        return;
    }

    free(file->content);
    file->content = content;
    file->size = size;
    file->capacity = size;
}

static int fsn_append_user_file(
    struct fsn_fuse_session *session,
    const char *path,
    mode_t mode,
    struct fsn_virtual_file **out_file
) {
    struct fsn_virtual_file *file;
    int result;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_is_user_file_path(path) || fsn_is_reserved_path(session, path)) {
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
    if (out_file != NULL) {
        *out_file = file;
    }
    return 0;
}

static int fsn_create_user_file(struct fsn_fuse_session *session, const char *path, mode_t mode) {
    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    return fsn_append_user_file(session, path, mode, NULL);
}

static int fsn_persist_created_user_file(struct fsn_fuse_session *session, const char *path, mode_t mode) {
    struct fsn_virtual_file *file;
    char host_path[PATH_MAX];
    int result;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    result = fsn_append_user_file(session, path, mode, &file);
    if (result != 0) {
        return result;
    }

    result = fsn_sync_user_file_to_backing_store(session, file);
    if (result != 0) {
        if (fsn_build_backing_store_file_path(session, path, host_path, sizeof(host_path)) == 0) {
            unlink(host_path);
        }
        fsn_free_virtual_file(file);
        session->user_file_count -= 1;
        return result;
    }

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

static int fsn_write_user_file_with_persistence(
    const struct fsn_fuse_session *session,
    struct fsn_virtual_file *file,
    const char *buf,
    size_t size,
    off_t off
) {
    char *snapshot_content;
    size_t snapshot_size;
    int result;
    int sync_result;

    result = fsn_snapshot_user_file(file, &snapshot_content, &snapshot_size);
    if (result != 0) {
        return result;
    }

    result = fsn_write_user_file(file, buf, size, off);
    if (result < 0) {
        free(snapshot_content);
        return result;
    }

    sync_result = fsn_sync_user_file_to_backing_store(session, file);
    if (sync_result != 0) {
        fsn_restore_user_file(file, snapshot_content, snapshot_size);
        fsn_sync_user_file_to_backing_store(session, file);
        return sync_result;
    }

    free(snapshot_content);
    return result;
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

static int fsn_truncate_user_file_with_persistence(
    const struct fsn_fuse_session *session,
    struct fsn_virtual_file *file,
    off_t size
) {
    char *snapshot_content;
    size_t snapshot_size;
    int result;
    int sync_result;

    result = fsn_snapshot_user_file(file, &snapshot_content, &snapshot_size);
    if (result != 0) {
        return result;
    }

    result = fsn_truncate_user_file(file, size);
    if (result != 0) {
        free(snapshot_content);
        return result;
    }

    sync_result = fsn_sync_user_file_to_backing_store(session, file);
    if (sync_result != 0) {
        fsn_restore_user_file(file, snapshot_content, snapshot_size);
        fsn_sync_user_file_to_backing_store(session, file);
        return sync_result;
    }

    free(snapshot_content);
    return 0;
}

static int fsn_change_user_file_mode_with_persistence(
    const struct fsn_fuse_session *session,
    const char *path,
    mode_t mode
) {
    struct fsn_virtual_file *file;
    char host_path[PATH_MAX];
    mode_t previous_mode;
    mode_t normalized_mode;
    int result;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    if (fsn_is_reserved_path(session, path)) {
        return -EACCES;
    }

    file = fsn_find_user_file((struct fsn_fuse_session *)session, path);
    if (file == NULL) {
        return -ENOENT;
    }

    result = fsn_build_backing_store_file_path(session, path, host_path, sizeof(host_path));
    if (result != 0) {
        return result;
    }

    previous_mode = file->mode;
    normalized_mode = (mode & 0777) == 0 ? previous_mode : (mode & 0777);
    file->mode = normalized_mode;

    if (chmod(host_path, normalized_mode) != 0) {
        file->mode = previous_mode;
        return -errno;
    }

    return 0;
}

static int fsn_sync_path(const struct fsn_fuse_session *session, const char *path) {
    const struct fsn_virtual_file *file;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (fsn_is_reserved_path(session, path)) {
        return 0;
    }

    file = fsn_find_user_file_const(session, path);
    if (file == NULL) {
        return -ENOENT;
    }

    return fsn_sync_user_file_to_backing_store(session, file);
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

static int fsn_remove_user_file_with_persistence(struct fsn_fuse_session *session, const char *path) {
    char host_path[PATH_MAX];
    int result;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    if (fsn_find_user_file(session, path) == NULL) {
        return -ENOENT;
    }

    result = fsn_build_backing_store_file_path(session, path, host_path, sizeof(host_path));
    if (result != 0) {
        return result;
    }

    if (unlink(host_path) != 0) {
        return -errno;
    }

    return fsn_remove_user_file(session, path);
}

static int fsn_rename_user_file_with_persistence(
    struct fsn_fuse_session *session,
    const char *from,
    const char *to
) {
    char source_host_path[PATH_MAX];
    char target_host_path[PATH_MAX];
    char *target_name;
    char *target_path;
    uint32_t source_index;
    uint32_t target_index;
    uint32_t index;
    int found_target;
    struct fsn_virtual_file *file;
    int result;

    if (session == NULL || from == NULL || to == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        return -EACCES;
    }

    if (!fsn_is_user_file_path(from) || !fsn_is_user_file_path(to)) {
        return -EINVAL;
    }

    if (fsn_is_reserved_path(session, from) || fsn_is_reserved_path(session, to)) {
        return -EACCES;
    }

    if (strcmp(from, to) == 0) {
        return 0;
    }

    source_index = 0;
    target_index = 0;
    found_target = 0;
    for (index = 0; index < session->user_file_count; index += 1) {
        if (strcmp(session->user_files[index].path, from) == 0) {
            source_index = index;
            found_target |= 2;
        } else if (strcmp(session->user_files[index].path, to) == 0) {
            target_index = index;
            found_target |= 1;
        }
    }

    if ((found_target & 2) == 0) {
        return -ENOENT;
    }

    target_name = fsn_strdup(to + 1);
    target_path = fsn_strdup(to);
    if (target_name == NULL || target_path == NULL) {
        free(target_name);
        free(target_path);
        return -ENOMEM;
    }

    result = fsn_build_backing_store_file_path(session, from, source_host_path, sizeof(source_host_path));
    if (result != 0) {
        free(target_name);
        free(target_path);
        return result;
    }

    result = fsn_build_backing_store_file_path(session, to, target_host_path, sizeof(target_host_path));
    if (result != 0) {
        free(target_name);
        free(target_path);
        return result;
    }

    if (rename(source_host_path, target_host_path) != 0) {
        free(target_name);
        free(target_path);
        return -errno;
    }

    if ((found_target & 1) != 0) {
        fsn_free_virtual_file(&session->user_files[target_index]);
        if (target_index + 1 < session->user_file_count) {
            memmove(
                &session->user_files[target_index],
                &session->user_files[target_index + 1],
                (size_t)(session->user_file_count - target_index - 1) * sizeof(*session->user_files)
            );
        }
        session->user_file_count -= 1;
        memset(&session->user_files[session->user_file_count], 0, sizeof(*session->user_files));
        if (target_index < source_index) {
            source_index -= 1;
        }
    }

    file = &session->user_files[source_index];
    free(file->name);
    free(file->path);
    file->name = target_name;
    file->path = target_path;
    return 0;
}

static int fsn_mutations_allowed(const struct fsn_fuse_session *session) {
    return session != NULL && session->allow_mutations != 0;
}

static int fsn_ensure_audit_capacity(struct fsn_fuse_session *session, uint32_t target) {
    struct fsn_audit_event *events;
    uint32_t capacity;

    if (target <= session->audit_event_capacity) {
        return FSN_FUSE_STATUS_OK;
    }

    capacity = session->audit_event_capacity == 0 ? 8 : session->audit_event_capacity * 2;
    while (capacity < target) {
        capacity *= 2;
    }

    events = realloc(session->audit_events, (size_t)capacity * sizeof(*events));
    if (events == NULL) {
        return FSN_FUSE_STATUS_OUT_OF_MEMORY;
    }

    memset(events + session->audit_event_capacity, 0, (size_t)(capacity - session->audit_event_capacity) * sizeof(*events));
    session->audit_events = events;
    session->audit_event_capacity = capacity;
    return FSN_FUSE_STATUS_OK;
}

static void fsn_free_audit_event(struct fsn_audit_event *event) {
    if (event == NULL) {
        return;
    }

    free(event->action);
    free(event->path);
    memset(event, 0, sizeof(*event));
}

static void fsn_record_audit_event(struct fsn_fuse_session *session, const char *action, const char *path, int32_t result) {
    struct fsn_audit_event *event;

    if (session == NULL || action == NULL || path == NULL) {
        return;
    }

    if (fsn_ensure_audit_capacity(session, session->audit_event_count + 1) != FSN_FUSE_STATUS_OK) {
        return;
    }

    event = &session->audit_events[session->audit_event_count];
    event->action = fsn_strdup(action);
    event->path = fsn_strdup(path);
    if (event->action == NULL || event->path == NULL) {
        fsn_free_audit_event(event);
        return;
    }

    event->result = result;
    session->audit_event_count += 1;
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
    if (fsn_is_status_path(session, path)) {
        char *content = fsn_render_status_content(session);

        if (content == NULL) {
            fsn_record_audit_event(session, "read", path, -ENOMEM);
            return -ENOMEM;
        }

        {
            int result = fsn_copy_read_slice(content, buf, size, off);
            free(content);
            fsn_record_audit_event(session, "read", path, result);
            return result;
        }
    }

    if (fsn_is_audit_path(session, path)) {
        char *content = fsn_render_audit_content(session);
        int result;

        if (content == NULL) {
            return -ENOMEM;
        }

        result = fsn_copy_read_slice(content, buf, size, off);
        free(content);
        return result;
    }

    {
        const struct fsn_virtual_file *file = fsn_find_user_file_const(session, path);
        if (file == NULL) {
            fsn_record_audit_event(session, "read", path, -ENOENT);
            return -ENOENT;
        }

        {
            int result = fsn_copy_buffer_slice(
                file->content != NULL ? file->content : "",
                file->size,
                buf,
                size,
                off
            );
            fsn_record_audit_event(session, "read", path, result);
            return result;
        }
    }
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
        fsn_record_audit_event(session, "write", path, -EACCES);
        return -EACCES;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        fsn_record_audit_event(session, "write", path, -ENOENT);
        return -ENOENT;
    }

    {
        int result = fsn_write_user_file_with_persistence(session, file, buf, size, off);
        fsn_record_audit_event(session, "write", path, result);
        return result;
    }
}

static int fsn_fuse_truncate(const char *path, off_t size) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    struct fsn_virtual_file *file;

    if (path == NULL) {
        return -EINVAL;
    }

    if (!fsn_mutations_allowed(session)) {
        fsn_record_audit_event(session, "truncate", path, -EACCES);
        return -EACCES;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        fsn_record_audit_event(session, "truncate", path, -ENOENT);
        return -ENOENT;
    }

    {
        int result = fsn_truncate_user_file_with_persistence(session, file, size);
        fsn_record_audit_event(session, "truncate", path, result);
        return result;
    }
}

static int fsn_fuse_chmod(const char *path, mode_t mode) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    int result;

    if (path == NULL) {
        return -EINVAL;
    }

    result = fsn_change_user_file_mode_with_persistence(session, path, mode);
    fsn_record_audit_event(session, "chmod", path, result);
    return result;
}

static int fsn_fuse_flush(const char *path, struct fuse_file_info *fi) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    int result;

    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    result = fsn_sync_path(session, path);
    fsn_record_audit_event(session, "flush", path, result);
    return result;
}

static int fsn_fuse_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    int result;

    (void)datasync;
    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    result = fsn_sync_path(session, path);
    fsn_record_audit_event(session, "fsync", path, result);
    return result;
}

static int fsn_fuse_unlink(const char *path) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;

    if (path == NULL) {
        return -EINVAL;
    }

    if (fsn_is_reserved_path(session, path)) {
        fsn_record_audit_event(session, "unlink", path, -EACCES);
        return -EACCES;
    }

    {
        int result = fsn_remove_user_file_with_persistence(session, path);
        fsn_record_audit_event(session, "unlink", path, result);
        return result;
    }
}

static int fsn_fuse_rename(const char *from, const char *to) {
    struct fsn_fuse_session *session = fuse_get_context()->private_data;
    char audit_path[(PATH_MAX * 2) + 8];
    int result;
    int written;

    if (from == NULL || to == NULL) {
        return -EINVAL;
    }

    if (fsn_is_reserved_path(session, from) || fsn_is_reserved_path(session, to)) {
        written = snprintf(audit_path, sizeof(audit_path), "%s -> %s", from, to);
        if (written < 0 || (size_t)written >= sizeof(audit_path)) {
            strcpy(audit_path, "<rename>");
        }
        fsn_record_audit_event(session, "rename", audit_path, -EACCES);
        return -EACCES;
    }

    result = fsn_rename_user_file_with_persistence(session, from, to);
    written = snprintf(audit_path, sizeof(audit_path), "%s -> %s", from, to);
    if (written < 0 || (size_t)written >= sizeof(audit_path)) {
        strcpy(audit_path, "<rename>");
    }
    fsn_record_audit_event(session, "rename", audit_path, result);
    return result;
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
    session->operations.chmod = fsn_fuse_chmod;
    session->operations.flush = fsn_fuse_flush;
    session->operations.fsync = fsn_fuse_fsync;
    session->operations.rename = fsn_fuse_rename;
    session->configured_operation_count = 16;
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
    session->next_inode = FSN_FIRST_DYNAMIC_INODE;
    fsn_fuse_configure_operations(session);
    if (fsn_build_execution_plan(session) != FSN_FUSE_STATUS_OK) {
        fsn_fuse_session_destroy(session);
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }
    if (fsn_build_audit_file(session) != FSN_FUSE_STATUS_OK) {
        fsn_fuse_session_destroy(session);
        return FSN_FUSE_STATUS_PLAN_BUILD_FAILED;
    }
    if (fsn_load_backing_store_files(session) != FSN_FUSE_STATUS_OK) {
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
    free(session->audit_file_name);
    free(session->audit_file_path);
    if (session->user_files != NULL) {
        uint32_t index;

        for (index = 0; index < session->user_file_count; index += 1) {
            fsn_free_virtual_file(&session->user_files[index]);
        }
    }
    free(session->user_files);
    if (session->audit_events != NULL) {
        uint32_t index;

        for (index = 0; index < session->audit_event_count; index += 1) {
            fsn_free_audit_event(&session->audit_events[index]);
        }
    }
    free(session->audit_events);
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
        session
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

    if (fsn_is_audit_path(session, path)) {
        fsn_fill_audit_stat(session, &stbuf);
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

    return 2 + session->user_file_count;
}

const char *fsn_fuse_debug_root_entry_at(const struct fsn_fuse_session *session, uint32_t index) {
    if (session == NULL || session->status_file_name == NULL) {
        return NULL;
    }

    if (index == 0) {
        return session->status_file_name;
    }

    if (index == 1) {
        return session->audit_file_name;
    }

    index -= 2;
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
        char *content = fsn_render_status_content(session);

        if (content == NULL) {
            fsn_record_audit_event((struct fsn_fuse_session *)session, "read", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        if (offset > (uint64_t)LLONG_MAX) {
            free(content);
            fsn_record_audit_event((struct fsn_fuse_session *)session, "read", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        {
            int result = fsn_copy_read_slice(content, buf, size, (off_t)offset);
            free(content);
            fsn_record_audit_event((struct fsn_fuse_session *)session, "read", path, result);
            return result;
        }
    }

    if (fsn_is_audit_path(session, path)) {
        char *content = fsn_render_audit_content(session);
        int result;

        if (content == NULL) {
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        if (offset > (uint64_t)LLONG_MAX) {
            free(content);
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        result = fsn_copy_read_slice(content, buf, size, (off_t)offset);
        free(content);
        return result;
    }

    {
        const struct fsn_virtual_file *file = fsn_find_user_file_const(session, path);
        if (file == NULL) {
            fsn_record_audit_event((struct fsn_fuse_session *)session, "read", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        if (offset > (uint64_t)LLONG_MAX) {
            fsn_record_audit_event((struct fsn_fuse_session *)session, "read", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
            return FSN_FUSE_STATUS_INVALID_ARGUMENT;
        }

        {
            int result = fsn_copy_buffer_slice(
                file->content != NULL ? file->content : "",
                file->size,
                buf,
                size,
                (off_t)offset
            );
            fsn_record_audit_event((struct fsn_fuse_session *)session, "read", path, result);
            return result;
        }
    }
}

int fsn_fuse_debug_create_file(struct fsn_fuse_session *session, const char *path, uint32_t mode) {
    if (session == NULL || path == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    {
        int result = fsn_persist_created_user_file(session, path, (mode_t)mode);
        fsn_record_audit_event(session, "create", path, result);
        return result;
    }
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
        fsn_record_audit_event(session, "write", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        fsn_record_audit_event(session, "write", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    {
        int result = fsn_write_user_file_with_persistence(session, file, buf, size, (off_t)offset);
        fsn_record_audit_event(session, "write", path, result);
        return result;
    }
}

int fsn_fuse_debug_truncate_file(struct fsn_fuse_session *session, const char *path, uint64_t size) {
    struct fsn_virtual_file *file;

    if (session == NULL || path == NULL || size > (uint64_t)LLONG_MAX) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    if (!fsn_mutations_allowed(session)) {
        fsn_record_audit_event(session, "truncate", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    file = fsn_find_user_file(session, path);
    if (file == NULL) {
        fsn_record_audit_event(session, "truncate", path, FSN_FUSE_STATUS_INVALID_ARGUMENT);
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    {
        int result = fsn_truncate_user_file_with_persistence(session, file, (off_t)size);
        fsn_record_audit_event(session, "truncate", path, result);
        return result;
    }
}

int fsn_fuse_debug_rename_file(struct fsn_fuse_session *session, const char *from, const char *to) {
    char audit_path[(PATH_MAX * 2) + 8];
    int result;
    int written;

    if (session == NULL || from == NULL || to == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    result = fsn_rename_user_file_with_persistence(session, from, to);
    written = snprintf(audit_path, sizeof(audit_path), "%s -> %s", from, to);
    if (written < 0 || (size_t)written >= sizeof(audit_path)) {
        strcpy(audit_path, "<rename>");
    }
    fsn_record_audit_event(session, "rename", audit_path, result);
    return result;
}

int fsn_fuse_debug_sync_file(struct fsn_fuse_session *session, const char *path, uint8_t datasync) {
    int result;

    (void)datasync;

    if (session == NULL || path == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    result = fsn_sync_path(session, path);
    fsn_record_audit_event(session, "fsync", path, result);
    return result;
}

int fsn_fuse_debug_remove_file(struct fsn_fuse_session *session, const char *path) {
    if (session == NULL || path == NULL) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    {
        int result = fsn_remove_user_file_with_persistence(session, path);
        fsn_record_audit_event(session, "unlink", path, result);
        return result;
    }
}

uint32_t fsn_fuse_debug_audit_count(const struct fsn_fuse_session *session) {
    if (session == NULL) {
        return 0;
    }

    return session->audit_event_count;
}

int fsn_fuse_debug_audit_event_at(
    const struct fsn_fuse_session *session,
    uint32_t index,
    struct fsn_fuse_audit_event *out
) {
    if (session == NULL || out == NULL || index >= session->audit_event_count) {
        return FSN_FUSE_STATUS_INVALID_ARGUMENT;
    }

    out->action = session->audit_events[index].action;
    out->path = session->audit_events[index].path;
    out->result = session->audit_events[index].result;
    return FSN_FUSE_STATUS_OK;
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
