#ifndef FILE_SNITCH_LIBFUSE_SHIM_H
#define FILE_SNITCH_LIBFUSE_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum fsn_fuse_status {
    FSN_FUSE_STATUS_OK = 0,
    FSN_FUSE_STATUS_INVALID_ARGUMENT = -1,
    FSN_FUSE_STATUS_OUT_OF_MEMORY = -2,
    FSN_FUSE_STATUS_NOT_IMPLEMENTED = -3,
};

struct fsn_fuse_environment {
    uint32_t fuse_major_version;
    uint32_t fuse_minor_version;
    size_t high_level_ops_size;
    uint8_t uses_c_shim;
    uint8_t reserved[7];
};

struct fsn_fuse_session;

struct fsn_fuse_session_config {
    const char *mount_path;
    const char *backing_store_path;
    void *daemon_state;
    uint8_t run_in_foreground;
    uint8_t reserved[3];
};

struct fsn_fuse_session_info {
    size_t high_level_ops_size;
    uint32_t configured_operation_count;
    uint8_t mount_implemented;
    uint8_t has_session_state;
    uint8_t has_daemon_state;
    uint8_t has_init_callback;
    uint8_t run_in_foreground;
    uint8_t reserved[3];
};

int fsn_fuse_probe(struct fsn_fuse_environment *out);
const char *fsn_fuse_backend_name(void);
int fsn_fuse_session_create(
    const struct fsn_fuse_session_config *config,
    struct fsn_fuse_session **out
);
void fsn_fuse_session_destroy(struct fsn_fuse_session *session);
int fsn_fuse_session_describe(
    const struct fsn_fuse_session *session,
    struct fsn_fuse_session_info *out
);
int fsn_fuse_session_run(struct fsn_fuse_session *session);
const char *fsn_fuse_session_mount_path(const struct fsn_fuse_session *session);
const char *fsn_fuse_session_backing_store_path(const struct fsn_fuse_session *session);
const char *fsn_fuse_status_label(int status);

#ifdef __cplusplus
}
#endif

#endif
