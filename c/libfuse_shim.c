#define FUSE_USE_VERSION 312

#include <fuse.h>
#include <string.h>

#include "libfuse_shim.h"

int fsn_fuse_probe(struct fsn_fuse_environment *out) {
    if (out == NULL) {
        return -1;
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
