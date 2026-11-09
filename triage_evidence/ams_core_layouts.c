#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <dlfcn.h>

struct creation_record {
    uint64_t original_x1;
    uint32_t encoded_operation;
    uint32_t padding12;
    uint64_t original_x3;
    uint64_t original_x0;
    uint32_t encoded_status;
    uint32_t padding36;
    uint64_t original_x2;
};

_Static_assert(sizeof(struct creation_record) == 48, "original wrapper record");
_Static_assert(offsetof(struct creation_record, encoded_operation) == 8, "operation");
_Static_assert(offsetof(struct creation_record, original_x3) == 16, "context output cell");
_Static_assert(offsetof(struct creation_record, encoded_status) == 32, "status");
_Static_assert(offsetof(struct creation_record, original_x2) == 40, "path");
_Static_assert(sizeof(pthread_rwlock_t) == 200, "allocated lock extent");
_Static_assert((RTLD_LAZY | RTLD_LOCAL) == 5, "CoreFP loader flags");
