#ifndef FILE_SNITCH_LIBFUSE_SHIM_H
#define FILE_SNITCH_LIBFUSE_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fsn_fuse_environment {
    uint32_t fuse_major_version;
    uint32_t fuse_minor_version;
    size_t high_level_ops_size;
    uint8_t uses_c_shim;
    uint8_t reserved[7];
};

int fsn_fuse_probe(struct fsn_fuse_environment *out);
const char *fsn_fuse_backend_name(void);

#ifdef __cplusplus
}
#endif

#endif
