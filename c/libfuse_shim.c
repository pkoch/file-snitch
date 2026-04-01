#define FUSE_USE_VERSION 312

#include <fuse.h>
#include <stdlib.h>
#include <string.h>

#include "libfuse_shim.h"

struct fsn_fuse_session {
    char *mount_path;
    char *backing_store_path;
    uint8_t run_in_foreground;
    struct fuse_operations operations;
};

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

    session->run_in_foreground = config->run_in_foreground != 0 ? 1 : 0;
    memset(&session->operations, 0, sizeof(session->operations));

    *out = session;
    return FSN_FUSE_STATUS_OK;
}

void fsn_fuse_session_destroy(struct fsn_fuse_session *session) {
    if (session == NULL) {
        return;
    }

    free(session->mount_path);
    free(session->backing_store_path);
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
    out->mount_implemented = 0;
    out->has_session_state = 1;
    out->run_in_foreground = session->run_in_foreground;
    return FSN_FUSE_STATUS_OK;
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
        default:
            return "unknown_status";
    }
}
