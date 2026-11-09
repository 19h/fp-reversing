#include <stdint.h>
#include <stddef.h>
#include <sys/xattr.h>

struct import_record {
    uint64_t purchaser_account_id;
    uint64_t downloader_account_id;
    uint64_t family_id;
    uint64_t unknown;
};

_Static_assert(sizeof(uint32_t) == 4, "u32 width");
_Static_assert(sizeof(uint64_t) == 8, "u64 width");
_Static_assert(sizeof(struct import_record) == 32, "original caller stride");
_Static_assert(offsetof(struct import_record, purchaser_account_id) == 0, "purchaser field");
_Static_assert(offsetof(struct import_record, downloader_account_id) == 8, "downloader field");
_Static_assert(offsetof(struct import_record, family_id) == 16, "family field");
_Static_assert(offsetof(struct import_record, unknown) == 24, "unconsumed field");
_Static_assert(XATTR_NOFOLLOW == 1, "reference xattr option");
