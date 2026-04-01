#define FUSE_USE_VERSION 312

#include <errno.h>
#include <fuse.h>
#include <stdlib.h>
#include <string.h>

#include "libfuse_shim.h"

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

static void *fsn_fuse_init(struct fuse_conn_info *conn) {
    (void)conn;
    return fuse_get_context()->private_data;
}

static void fsn_fuse_destroy(void *private_data) {
    (void)private_data;
}

static int fsn_fuse_getattr(const char *path, struct stat *stbuf) {
    (void)path;
    (void)stbuf;
    return -ENOENT;
}

static int fsn_fuse_readdir(
    const char *path,
    void *buf,
    fuse_fill_dir_t filler,
    off_t off,
    struct fuse_file_info *fi
) {
    (void)path;
    (void)buf;
    (void)filler;
    (void)off;
    (void)fi;
    return -ENOENT;
}

static int fsn_fuse_open(const char *path, struct fuse_file_info *fi) {
    (void)path;
    (void)fi;
    return -ENOENT;
}

static int fsn_fuse_read(
    const char *path,
    char *buf,
    size_t size,
    off_t off,
    struct fuse_file_info *fi
) {
    (void)path;
    (void)buf;
    (void)size;
    (void)off;
    (void)fi;
    return -ENOENT;
}

static void fsn_fuse_configure_operations(struct fsn_fuse_session *session) {
    memset(&session->operations, 0, sizeof(session->operations));
    session->operations.init = fsn_fuse_init;
    session->operations.destroy = fsn_fuse_destroy;
    session->operations.getattr = fsn_fuse_getattr;
    session->operations.readdir = fsn_fuse_readdir;
    session->operations.open = fsn_fuse_open;
    session->operations.read = fsn_fuse_read;
    session->configured_operation_count = 5;
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
