/* Partial ABI views checked against retained native offsets. */
typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;
typedef unsigned char u8;
#define OFF(T,F) __builtin_offsetof(T,F)
struct kernel_header {
    u32 bits, size;
    u64 remote, local;
    u32 voucher, id;
};
struct __attribute__((packed,aligned(4))) kernel_ool {
    u64 address;
    u8 deallocate, copy, padding, type;
    u32 extent;
};
struct kernel_request_prefix {
    struct kernel_header header;
    u32 descriptor_count;
    struct kernel_ool ool;
};
struct normal_kernel_reply_storage {
    u8 inline_message[392];
    u32 trailer_type, trailer_extent;
};
_Static_assert(sizeof(struct kernel_header)==32,"kernel header bytes");
_Static_assert(OFF(struct kernel_header,remote)==8,"destination pointer");
_Static_assert(OFF(struct kernel_header,local)==16,"reply pointer");
_Static_assert(sizeof(struct kernel_ool)==16,"kernel descriptor bytes");
_Static_assert(OFF(struct kernel_ool,type)==11,"descriptor tag");
_Static_assert(OFF(struct kernel_request_prefix,descriptor_count)==32,"count");
_Static_assert(OFF(struct kernel_request_prefix,ool)==36,"descriptor");
_Static_assert(sizeof(struct normal_kernel_reply_storage)==400,"receive capacity");
_Static_assert(OFF(struct normal_kernel_reply_storage,trailer_type)==392,"trailer");
