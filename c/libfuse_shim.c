#define FUSE_USE_VERSION 312

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __APPLE__
#include <sys/xattr.h>
#endif
#include <time.h>
#include <unistd.h>

#include "libfuse_shim.h"

enum fsn_access_class {
    FSN_ACCESS_READ = 1,
    FSN_ACCESS_CREATE = 2,
    FSN_ACCESS_WRITE = 3,
    FSN_ACCESS_RENAME = 4,
    FSN_ACCESS_DELETE = 5,
    FSN_ACCESS_METADATA = 6,
    FSN_ACCESS_XATTR = 7,
};

enum fsn_node_kind {
    FSN_NODE_MISSING = 0,
    FSN_NODE_DIRECTORY = 1,
    FSN_NODE_REGULAR_FILE = 2,
};

enum fsn_open_kind {
    FSN_OPEN_MISSING = 0,
    FSN_OPEN_DIRECTORY = 1,
    FSN_OPEN_SYNTHETIC_READONLY = 2,
    FSN_OPEN_USER_FILE = 3,
};

struct fsn_bridge_request {
    const char *path;
    uint32_t access_class;
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint8_t reserved[4];
};

struct fsn_bridge_lookup {
    uint32_t kind;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t inode;
    uint8_t open_kind;
    uint8_t persistent;
    uint8_t reserved[6];
};

extern int fsn_daemon_lookup_path(void *daemon_state, const char *path, struct fsn_bridge_lookup *out);
extern uint32_t fsn_daemon_root_entry_count(void *daemon_state);
extern const char *fsn_daemon_root_entry_name_at(void *daemon_state, uint32_t index);
extern int fsn_daemon_authorize_access(void *daemon_state, const struct fsn_bridge_request *request);
extern int fsn_daemon_read(
    void *daemon_state,
    const struct fsn_bridge_request *request,
    uint64_t offset,
    size_t size,
    char *buf
);
extern int fsn_daemon_create(void *daemon_state, const struct fsn_bridge_request *request, uint32_t mode);
extern int fsn_daemon_mkdir(void *daemon_state, const struct fsn_bridge_request *request, uint32_t mode);
extern int fsn_daemon_write(
    void *daemon_state,
    const struct fsn_bridge_request *request,
    uint64_t offset,
    size_t size,
    const char *buf
);
extern int fsn_daemon_truncate(void *daemon_state, const struct fsn_bridge_request *request, uint64_t size);
extern int fsn_daemon_chmod(void *daemon_state, const struct fsn_bridge_request *request, uint32_t mode);
extern int fsn_daemon_chown(void *daemon_state, const struct fsn_bridge_request *request, uint32_t uid, uint32_t gid);
extern int fsn_daemon_sync(void *daemon_state, const struct fsn_bridge_request *request, uint8_t datasync);
extern int fsn_daemon_unlink(void *daemon_state, const struct fsn_bridge_request *request);
extern int fsn_daemon_rmdir(void *daemon_state, const struct fsn_bridge_request *request);
extern int fsn_daemon_rename(void *daemon_state, const struct fsn_bridge_request *request, const char *to_path);
extern int fsn_daemon_record_audit(void *daemon_state, const char *action, const char *path, int32_t result);

struct fsn_file_handle {
    int backing_fd;
};

struct fsn_fuse_session {
    char *mount_path;
    char *backing_store_path;
    void *daemon_state;
    uint8_t run_in_foreground;
    uint32_t configured_operation_count;
    uint32_t planned_argument_count;
    char **planned_arguments;
    struct fuse_operations operations;
};

static char *fsn_strdup(const char *value);
static int fsn_is_root_path(const char *path);
static int fsn_is_user_file_path(const char *path);
static int fsn_build_request(
    struct fsn_bridge_request *out,
    const char *path,
    uint32_t access_class,
    int use_fuse_context
);
static int fsn_lookup_path(
    const struct fsn_fuse_session *session,
    const char *path,
    struct fsn_bridge_lookup *out
);
static void fsn_fill_stat_from_lookup(const struct fsn_bridge_lookup *lookup, struct stat *stbuf);
static int fsn_build_virtual_path(const char *name, char *buf, size_t buf_size);
static int fsn_build_backing_store_path(
    const struct fsn_fuse_session *session,
    const char *path,
    char *buf,
    size_t buf_size
);
static void fsn_record_audit(
    const struct fsn_fuse_session *session,
    const char *action,
    const char *path,
    int32_t result
);
static struct fsn_file_handle *fsn_create_file_handle(void);
static struct fsn_file_handle *fsn_get_file_handle(const struct fuse_file_info *fi);
static void fsn_clear_file_handle(struct fuse_file_info *fi);
static int fsn_open_backing_store_fd(
    const struct fsn_fuse_session *session,
    const char *path,
    int requested_flags
);
static void fsn_fuse_configure_operations(struct fsn_fuse_session *session);
static void fsn_free_planned_arguments(struct fsn_fuse_session *session);
static int fsn_push_argument(struct fsn_fuse_session *session, const char *value);
static int fsn_build_execution_plan(struct fsn_fuse_session *session);
static char **fsn_duplicate_argument_vector(const struct fsn_fuse_session *session);
static void fsn_free_argument_vector(char **argv, uint32_t argc);

static void *fsn_fuse_init(struct fuse_conn_info *conn) {
    if (conn != NULL) {
        conn->want |= FUSE_CAP_POSIX_LOCKS;
        conn->want |= FUSE_CAP_FLOCK_LOCKS;
    }

    return fuse_get_context()->private_data;
}

static void fsn_fuse_destroy(void *private_data) {
    (void)private_data;
}

static int fsn_fuse_getattr(const char *path, struct stat *stbuf) {
    struct fsn_bridge_lookup lookup;

    if (path == NULL || stbuf == NULL) {
        return -EINVAL;
    }

    if (fsn_lookup_path(fuse_get_context()->private_data, path, &lookup) != 0) {
        return -EIO;
    }

    if (lookup.kind == FSN_NODE_MISSING) {
        return -ENOENT;
    }

    fsn_fill_stat_from_lookup(&lookup, stbuf);
    return 0;
}

static int fsn_fuse_opendir(const char *path, struct fuse_file_info *fi) {
    struct fsn_bridge_lookup lookup;

    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    if (fsn_lookup_path(fuse_get_context()->private_data, path, &lookup) != 0) {
        return -EIO;
    }

    return lookup.open_kind == FSN_OPEN_DIRECTORY ? 0 : -ENOENT;
}

static int fsn_fuse_readdir(
    const char *path,
    void *buf,
    fuse_fill_dir_t filler,
    off_t off,
    struct fuse_file_info *fi
) {
    struct stat stbuf;
    struct fsn_bridge_lookup directory_lookup;
    struct fsn_fuse_session *session;
    uint32_t count;
    uint32_t index;

    (void)off;
    (void)fi;

    if (path == NULL || buf == NULL || filler == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_lookup_path(session, path, &directory_lookup) != 0) {
        return -EIO;
    }

    if (directory_lookup.open_kind != FSN_OPEN_DIRECTORY) {
        return -ENOENT;
    }

    memset(&stbuf, 0, sizeof(stbuf));
    fsn_fill_stat_from_lookup(&directory_lookup, &stbuf);
    if (filler(buf, ".", &stbuf, 0) != 0) {
        return 0;
    }

    if (filler(buf, "..", &stbuf, 0) != 0) {
        return 0;
    }

    if (!fsn_is_root_path(path)) {
        return 0;
    }

    count = fsn_daemon_root_entry_count(session->daemon_state);
    for (index = 0; index < count; index += 1) {
        const char *name = fsn_daemon_root_entry_name_at(session->daemon_state, index);
        struct fsn_bridge_lookup lookup;
        char virtual_path[PATH_MAX];

        if (name == NULL) {
            return -EIO;
        }

        if (fsn_build_virtual_path(name, virtual_path, sizeof(virtual_path)) != 0) {
            return -ENAMETOOLONG;
        }

        if (fsn_lookup_path(session, virtual_path, &lookup) != 0) {
            return -EIO;
        }

        memset(&stbuf, 0, sizeof(stbuf));
        fsn_fill_stat_from_lookup(&lookup, &stbuf);
        if (filler(buf, name, &stbuf, 0) != 0) {
            return 0;
        }
    }

    return 0;
}

static int fsn_fuse_releasedir(const char *path, struct fuse_file_info *fi) {
    struct fsn_bridge_lookup lookup;

    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    if (fsn_lookup_path(fuse_get_context()->private_data, path, &lookup) != 0) {
        return -EIO;
    }

    return lookup.open_kind == FSN_OPEN_DIRECTORY ? 0 : -ENOENT;
}

static int fsn_fuse_open(const char *path, struct fuse_file_info *fi) {
    struct fsn_bridge_lookup lookup;
    struct fsn_fuse_session *session;

    if (path == NULL || fi == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_lookup_path(session, path, &lookup) != 0) {
        return -EIO;
    }

    switch (lookup.open_kind) {
        case FSN_OPEN_SYNTHETIC_READONLY:
            if ((fi->flags & O_ACCMODE) != O_RDONLY) {
                return -EACCES;
            }
            break;
        case FSN_OPEN_USER_FILE:
            if (lookup.persistent != 0) {
                struct fsn_file_handle *handle = fsn_create_file_handle();
                int backing_fd;

                if (handle == NULL) {
                    return -ENOMEM;
                }

                backing_fd = fsn_open_backing_store_fd(session, path, fi->flags);
                if (backing_fd < 0) {
                    free(handle);
                    return backing_fd;
                }

                handle->backing_fd = backing_fd;
                fi->fh = (uint64_t)(uintptr_t)handle;
            }
            break;
        case FSN_OPEN_DIRECTORY:
            return -EISDIR;
        default:
            return -ENOENT;
    }

    fi->direct_io = 1;
    fi->keep_cache = 0;
    return 0;
}

static int fsn_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct fsn_bridge_request request;
    struct fsn_bridge_lookup lookup;
    struct fsn_fuse_session *session;
    int result;

    if (path == NULL || fi == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    result = fsn_build_request(&request, path, FSN_ACCESS_CREATE, 1);
    if (result != 0) {
        return result;
    }

    result = fsn_daemon_create(session->daemon_state, &request, (uint32_t)mode);
    if (result != 0) {
        return result;
    }

    if (fsn_lookup_path(session, path, &lookup) != 0) {
        return -EIO;
    }

    if (lookup.persistent != 0) {
        struct fsn_file_handle *handle = fsn_create_file_handle();
        int backing_fd;

        if (handle == NULL) {
            return -ENOMEM;
        }

        backing_fd = fsn_open_backing_store_fd(session, path, O_RDWR);
        if (backing_fd < 0) {
            free(handle);
            return backing_fd;
        }

        handle->backing_fd = backing_fd;
        fi->fh = (uint64_t)(uintptr_t)handle;
    }

    fi->direct_io = 1;
    fi->keep_cache = 0;
    return 0;
}

static int fsn_fuse_mkdir(const char *path, mode_t mode) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_CREATE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_mkdir(session->daemon_state, &request, (uint32_t)mode);
}

static int fsn_fuse_release(const char *path, struct fuse_file_info *fi) {
    if (path == NULL) {
        return -EINVAL;
    }

    fsn_clear_file_handle(fi);
    return 0;
}

static int fsn_fuse_read(
    const char *path,
    char *buf,
    size_t size,
    off_t off,
    struct fuse_file_info *fi
) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    (void)fi;

    if (path == NULL || buf == NULL || off < 0) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_READ, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_read(session->daemon_state, &request, (uint64_t)off, size, buf);
}

static int fsn_fuse_write(
    const char *path,
    const char *buf,
    size_t size,
    off_t off,
    struct fuse_file_info *fi
) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    (void)fi;

    if (path == NULL || buf == NULL || off < 0) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_WRITE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_write(session->daemon_state, &request, (uint64_t)off, size, buf);
}

static int fsn_fuse_truncate(const char *path, off_t size) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (path == NULL || size < 0) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_WRITE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_truncate(session->daemon_state, &request, (uint64_t)size);
}

static int fsn_fuse_chmod(const char *path, mode_t mode) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_METADATA, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_chmod(session->daemon_state, &request, (uint32_t)mode);
}

static int fsn_fuse_chown(const char *path, uid_t uid, gid_t gid) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_METADATA, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_chown(session->daemon_state, &request, (uint32_t)uid, (uint32_t)gid);
}

static int fsn_fuse_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock) {
    struct fsn_bridge_lookup lookup;
    struct fsn_file_handle *handle;
    struct fsn_fuse_session *session;
    int result;

    if (path == NULL || fi == NULL || lock == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_lookup_path(session, path, &lookup) != 0) {
        return -EIO;
    }

    if (lookup.open_kind != FSN_OPEN_USER_FILE) {
        fsn_record_audit(session, "lock", path, -ENOENT);
        return -ENOENT;
    }

    handle = fsn_get_file_handle(fi);
    if (handle == NULL) {
        fsn_record_audit(session, "lock", path, -EBADF);
        return -EBADF;
    }

    result = fcntl(handle->backing_fd, cmd, lock);
    if (result != 0) {
        result = -errno;
    }

    fsn_record_audit(session, "lock", path, result);
    return result;
}

static int fsn_fuse_flock(const char *path, struct fuse_file_info *fi, int op) {
    struct fsn_bridge_lookup lookup;
    struct fsn_file_handle *handle;
    struct fsn_fuse_session *session;
    int result;

    if (path == NULL || fi == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_lookup_path(session, path, &lookup) != 0) {
        return -EIO;
    }

    if (lookup.open_kind != FSN_OPEN_USER_FILE) {
        fsn_record_audit(session, "flock", path, -ENOENT);
        return -ENOENT;
    }

    handle = fsn_get_file_handle(fi);
    if (handle == NULL) {
        fsn_record_audit(session, "flock", path, -EBADF);
        return -EBADF;
    }

    result = flock(handle->backing_fd, op);
    if (result != 0) {
        result = -errno;
    }

    fsn_record_audit(session, "flock", path, result);
    return result;
}

#ifdef __APPLE__
static int fsn_fuse_setxattr(
    const char *path,
    const char *name,
    const char *value,
    size_t size,
    int flags,
    uint32_t position
) {
    struct fsn_bridge_request request;
    struct fsn_bridge_lookup lookup;
    struct fsn_fuse_session *session;
    char host_path[PATH_MAX];
    int result;

    if (path == NULL || name == NULL || value == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_XATTR, 1) != 0) {
        return -EINVAL;
    }

    result = fsn_daemon_authorize_access(session->daemon_state, &request);
    if (result == 0) {
        if (fsn_lookup_path(session, path, &lookup) != 0) {
            result = -EIO;
        } else if (lookup.open_kind != FSN_OPEN_USER_FILE || lookup.persistent == 0) {
            result = -ENOENT;
        } else if (fsn_build_backing_store_path(session, path, host_path, sizeof(host_path)) != 0) {
            result = -ENAMETOOLONG;
        } else if (setxattr(host_path, name, value, size, position, flags) != 0) {
            result = -errno;
        }
    }

    fsn_record_audit(session, "setxattr", path, result);
    return result;
}

static int fsn_fuse_getxattr(
    const char *path,
    const char *name,
    char *value,
    size_t size,
    uint32_t position
) {
    struct fsn_bridge_request request;
    struct fsn_bridge_lookup lookup;
    struct fsn_fuse_session *session;
    char host_path[PATH_MAX];
    ssize_t result;

    if (path == NULL || name == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_XATTR, 1) != 0) {
        return -EINVAL;
    }

    result = fsn_daemon_authorize_access(session->daemon_state, &request);
    if (result != 0) {
        fsn_record_audit(session, "getxattr", path, (int32_t)result);
        return (int)result;
    }

    if (fsn_lookup_path(session, path, &lookup) != 0) {
        result = -EIO;
    } else if (lookup.open_kind != FSN_OPEN_USER_FILE || lookup.persistent == 0) {
        result = -ENOENT;
    } else if (fsn_build_backing_store_path(session, path, host_path, sizeof(host_path)) != 0) {
        result = -ENAMETOOLONG;
    } else {
        result = getxattr(host_path, name, value, size, position, 0);
        if (result < 0) {
            result = -errno;
        }
    }

    fsn_record_audit(session, "getxattr", path, (int32_t)result);
    return (int)result;
}

static int fsn_fuse_listxattr(const char *path, char *list, size_t size) {
    struct fsn_bridge_request request;
    struct fsn_bridge_lookup lookup;
    struct fsn_fuse_session *session;
    char host_path[PATH_MAX];
    ssize_t result;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_XATTR, 1) != 0) {
        return -EINVAL;
    }

    result = fsn_daemon_authorize_access(session->daemon_state, &request);
    if (result != 0) {
        fsn_record_audit(session, "listxattr", path, (int32_t)result);
        return (int)result;
    }

    if (fsn_lookup_path(session, path, &lookup) != 0) {
        result = -EIO;
    } else if (lookup.open_kind != FSN_OPEN_USER_FILE || lookup.persistent == 0) {
        result = -ENOENT;
    } else if (fsn_build_backing_store_path(session, path, host_path, sizeof(host_path)) != 0) {
        result = -ENAMETOOLONG;
    } else {
        result = listxattr(host_path, list, size, 0);
        if (result < 0) {
            result = -errno;
        }
    }

    fsn_record_audit(session, "listxattr", path, (int32_t)result);
    return (int)result;
}

static int fsn_fuse_removexattr(const char *path, const char *name) {
    struct fsn_bridge_request request;
    struct fsn_bridge_lookup lookup;
    struct fsn_fuse_session *session;
    char host_path[PATH_MAX];
    int result;

    if (path == NULL || name == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_XATTR, 1) != 0) {
        return -EINVAL;
    }

    result = fsn_daemon_authorize_access(session->daemon_state, &request);
    if (result == 0) {
        if (fsn_lookup_path(session, path, &lookup) != 0) {
            result = -EIO;
        } else if (lookup.open_kind != FSN_OPEN_USER_FILE || lookup.persistent == 0) {
            result = -ENOENT;
        } else if (fsn_build_backing_store_path(session, path, host_path, sizeof(host_path)) != 0) {
            result = -ENAMETOOLONG;
        } else if (removexattr(host_path, name, 0) != 0) {
            result = -errno;
        }
    }

    fsn_record_audit(session, "removexattr", path, result);
    return result;
}
#endif

static int fsn_fuse_flush(const char *path, struct fuse_file_info *fi) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_WRITE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_sync(session->daemon_state, &request, 0);
}

static int fsn_fuse_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    (void)fi;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_WRITE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_sync(session->daemon_state, &request, datasync != 0 ? 1 : 0);
}

static int fsn_fuse_unlink(const char *path) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_DELETE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_unlink(session->daemon_state, &request);
}

static int fsn_fuse_rmdir(const char *path) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (path == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, path, FSN_ACCESS_DELETE, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_rmdir(session->daemon_state, &request);
}

static int fsn_fuse_rename(const char *from, const char *to) {
    struct fsn_bridge_request request;
    struct fsn_fuse_session *session;

    if (from == NULL || to == NULL) {
        return -EINVAL;
    }

    session = fuse_get_context()->private_data;
    if (fsn_build_request(&request, from, FSN_ACCESS_RENAME, 1) != 0) {
        return -EINVAL;
    }

    return fsn_daemon_rename(session->daemon_state, &request, to);
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
    session->operations.mkdir = fsn_fuse_mkdir;
    session->operations.unlink = fsn_fuse_unlink;
    session->operations.rmdir = fsn_fuse_rmdir;
    session->operations.open = fsn_fuse_open;
    session->operations.release = fsn_fuse_release;
    session->operations.read = fsn_fuse_read;
    session->operations.write = fsn_fuse_write;
    session->operations.truncate = fsn_fuse_truncate;
    session->operations.chmod = fsn_fuse_chmod;
    session->operations.chown = fsn_fuse_chown;
    session->operations.lock = fsn_fuse_lock;
    session->operations.flock = fsn_fuse_flock;
#ifdef __APPLE__
    session->operations.setxattr = fsn_fuse_setxattr;
    session->operations.getxattr = fsn_fuse_getxattr;
    session->operations.listxattr = fsn_fuse_listxattr;
    session->operations.removexattr = fsn_fuse_removexattr;
    session->configured_operation_count = 25;
#else
    session->configured_operation_count = 21;
#endif
    session->operations.flush = fsn_fuse_flush;
    session->operations.fsync = fsn_fuse_fsync;
    session->operations.rename = fsn_fuse_rename;
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
    fsn_fuse_configure_operations(session);
    if (fsn_build_execution_plan(session) != FSN_FUSE_STATUS_OK) {
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
    if (fuse == NULL) {
        fsn_free_argument_vector(argv, session->planned_argument_count);
        return FSN_FUSE_STATUS_SETUP_FAILED;
    }

    loop_result = multithreaded != 0 ? fuse_loop_mt(fuse) : fuse_loop(fuse);
    fuse_teardown(fuse, mountpoint);
    fsn_free_argument_vector(argv, session->planned_argument_count);
    if (loop_result != 0) {
        return FSN_FUSE_STATUS_LOOP_FAILED;
    }

    return FSN_FUSE_STATUS_OK;
}

uint32_t fsn_fuse_session_argument_count(const struct fsn_fuse_session *session) {
    return session == NULL ? 0 : session->planned_argument_count;
}

const char *fsn_fuse_session_argument_at(const struct fsn_fuse_session *session, uint32_t index) {
    if (session == NULL || index >= session->planned_argument_count) {
        return NULL;
    }

    return session->planned_arguments[index];
}

const char *fsn_fuse_status_label(int status) {
    switch (status) {
        case FSN_FUSE_STATUS_OK:
            return "ok";
        case FSN_FUSE_STATUS_INVALID_ARGUMENT:
            return "invalid argument";
        case FSN_FUSE_STATUS_OUT_OF_MEMORY:
            return "out of memory";
        case FSN_FUSE_STATUS_PLAN_BUILD_FAILED:
            return "execution plan build failed";
        case FSN_FUSE_STATUS_SETUP_FAILED:
            return "fuse setup failed";
        case FSN_FUSE_STATUS_LOOP_FAILED:
            return "fuse loop failed";
        default:
            return "unknown";
    }
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

static int fsn_build_request(
    struct fsn_bridge_request *out,
    const char *path,
    uint32_t access_class,
    int use_fuse_context
) {
    struct fuse_context *context;

    if (out == NULL || path == NULL) {
        return -EINVAL;
    }

    memset(out, 0, sizeof(*out));
    out->path = path;
    out->access_class = access_class;
    if (!use_fuse_context) {
        return 0;
    }

    context = fuse_get_context();
    if (context != NULL) {
        out->pid = (uint32_t)context->pid;
        out->uid = (uint32_t)context->uid;
        out->gid = (uint32_t)context->gid;
    }

    return 0;
}

static int fsn_lookup_path(
    const struct fsn_fuse_session *session,
    const char *path,
    struct fsn_bridge_lookup *out
) {
    if (session == NULL || path == NULL || out == NULL || session->daemon_state == NULL) {
        return -EINVAL;
    }

    return fsn_daemon_lookup_path(session->daemon_state, path, out);
}

static void fsn_fill_stat_from_lookup(const struct fsn_bridge_lookup *lookup, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = (lookup->kind == FSN_NODE_DIRECTORY ? S_IFDIR : S_IFREG) | lookup->mode;
    stbuf->st_nlink = lookup->kind == FSN_NODE_DIRECTORY ? 2 : 1;
    stbuf->st_uid = lookup->uid;
    stbuf->st_gid = lookup->gid;
    stbuf->st_size = (off_t)lookup->size;
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    stbuf->st_ino = (ino_t)lookup->inode;
}

static int fsn_build_virtual_path(const char *name, char *buf, size_t buf_size) {
    int written;

    if (name == NULL || buf == NULL || buf_size == 0) {
        return -EINVAL;
    }

    written = snprintf(buf, buf_size, "/%s", name);
    if (written < 0 || (size_t)written >= buf_size) {
        return -ENAMETOOLONG;
    }

    return 0;
}

static int fsn_build_backing_store_path(
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

static void fsn_record_audit(
    const struct fsn_fuse_session *session,
    const char *action,
    const char *path,
    int32_t result
) {
    if (session == NULL || session->daemon_state == NULL || action == NULL || path == NULL) {
        return;
    }

    fsn_daemon_record_audit(session->daemon_state, action, path, result);
}

static struct fsn_file_handle *fsn_create_file_handle(void) {
    struct fsn_file_handle *handle = calloc(1, sizeof(*handle));

    if (handle == NULL) {
        return NULL;
    }

    handle->backing_fd = -1;
    return handle;
}

static struct fsn_file_handle *fsn_get_file_handle(const struct fuse_file_info *fi) {
    if (fi == NULL || fi->fh == 0) {
        return NULL;
    }

    return (struct fsn_file_handle *)(uintptr_t)fi->fh;
}

static void fsn_clear_file_handle(struct fuse_file_info *fi) {
    struct fsn_file_handle *handle;

    if (fi == NULL || fi->fh == 0) {
        return;
    }

    handle = (struct fsn_file_handle *)(uintptr_t)fi->fh;
    if (handle != NULL) {
        if (handle->backing_fd >= 0) {
            close(handle->backing_fd);
        }
        free(handle);
    }

    fi->fh = 0;
}

static int fsn_open_backing_store_fd(
    const struct fsn_fuse_session *session,
    const char *path,
    int requested_flags
) {
    char host_path[PATH_MAX];
    int access_mode;
    int open_flags;
    int path_result;
    int descriptor;

    if (session == NULL || path == NULL) {
        return -EINVAL;
    }

    path_result = fsn_build_backing_store_path(session, path, host_path, sizeof(host_path));
    if (path_result != 0) {
        return path_result;
    }

    access_mode = requested_flags & O_ACCMODE;
    open_flags = access_mode == O_RDONLY ? O_RDONLY : O_RDWR;
    descriptor = open(host_path, open_flags);
    if (descriptor < 0) {
        return -errno;
    }

    return descriptor;
}
