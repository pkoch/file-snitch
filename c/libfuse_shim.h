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
    FSN_FUSE_STATUS_PLAN_BUILD_FAILED = -4,
    FSN_FUSE_STATUS_SETUP_FAILED = -5,
    FSN_FUSE_STATUS_LOOP_FAILED = -6,
};

enum fsn_fuse_node_kind {
    FSN_FUSE_NODE_MISSING = 0,
    FSN_FUSE_NODE_DIRECTORY = 1,
    FSN_FUSE_NODE_REGULAR_FILE = 2,
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
    uint8_t allow_mutations;
    uint8_t reserved[2];
};

struct fsn_fuse_session_info {
    size_t high_level_ops_size;
    uint32_t configured_operation_count;
    uint32_t planned_argument_count;
    uint8_t mount_implemented;
    uint8_t has_session_state;
    uint8_t has_daemon_state;
    uint8_t has_init_callback;
    uint8_t run_in_foreground;
    uint8_t allow_mutations;
    uint8_t reserved[6];
};

struct fsn_fuse_node_info {
    uint32_t kind;
    uint32_t mode;
    uint64_t size;
    uint64_t inode;
};

struct fsn_fuse_audit_event {
    const char *action;
    const char *path;
    int32_t result;
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
uint32_t fsn_fuse_session_argument_count(const struct fsn_fuse_session *session);
const char *fsn_fuse_session_argument_at(const struct fsn_fuse_session *session, uint32_t index);
int fsn_fuse_debug_getattr(
    const struct fsn_fuse_session *session,
    const char *path,
    struct fsn_fuse_node_info *out
);
uint32_t fsn_fuse_debug_root_entry_count(const struct fsn_fuse_session *session);
const char *fsn_fuse_debug_root_entry_at(const struct fsn_fuse_session *session, uint32_t index);
int fsn_fuse_debug_read(
    const struct fsn_fuse_session *session,
    const char *path,
    uint64_t offset,
    size_t size,
    char *buf
);
int fsn_fuse_debug_create_file(
    struct fsn_fuse_session *session,
    const char *path,
    uint32_t mode
);
int fsn_fuse_debug_write_file(
    struct fsn_fuse_session *session,
    const char *path,
    uint64_t offset,
    size_t size,
    const char *buf
);
int fsn_fuse_debug_truncate_file(
    struct fsn_fuse_session *session,
    const char *path,
    uint64_t size
);
int fsn_fuse_debug_rename_file(
    struct fsn_fuse_session *session,
    const char *from,
    const char *to
);
int fsn_fuse_debug_sync_file(
    struct fsn_fuse_session *session,
    const char *path,
    uint8_t datasync
);
int fsn_fuse_debug_remove_file(struct fsn_fuse_session *session, const char *path);
uint32_t fsn_fuse_debug_audit_count(const struct fsn_fuse_session *session);
int fsn_fuse_debug_audit_event_at(
    const struct fsn_fuse_session *session,
    uint32_t index,
    struct fsn_fuse_audit_event *out
);
const char *fsn_fuse_session_mount_path(const struct fsn_fuse_session *session);
const char *fsn_fuse_session_backing_store_path(const struct fsn_fuse_session *session);
const char *fsn_fuse_status_label(int status);

#ifdef __cplusplus
}
#endif

#endif
