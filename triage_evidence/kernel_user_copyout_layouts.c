/* Native-checked partial views; no assertion of complete private structures. */
typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;
typedef unsigned char u8;
#define OFF(T,F) __builtin_offsetof(T,F)
struct user_header { u32 bits, size, remote, local, voucher, id; };
struct __attribute__((packed,aligned(4))) ool64 {
    u64 address;
    u32 flags, extent;
};
struct ool32 { u32 address, extent, flags; };
struct __attribute__((packed,aligned(4))) request64 {
    struct user_header header;
    u32 count;
    struct ool64 ool;
    u8 ndr[8];
    u32 repeated_extent;
    u64 cpu, subtype, origin;
};
struct audit_trailer_prefix {
    u32 type, advertised_size, sequence;
    u32 security[2];
    u32 audit[8];
};
_Static_assert(sizeof(struct user_header)==24,"user header");
_Static_assert(sizeof(struct ool64)==16,"64-bit OOL descriptor");
_Static_assert(sizeof(struct ool32)==12,"32-bit OOL descriptor");
_Static_assert(OFF(struct request64,ool)==0x1c,"descriptor");
_Static_assert(OFF(struct request64,repeated_extent)==0x34,"repeated length");
_Static_assert(OFF(struct request64,cpu)==0x38,"CPU scalar");
_Static_assert(sizeof(struct request64)==80,"user request bytes");
_Static_assert(OFF(struct audit_trailer_prefix,audit)==20,"audit bytes");
_Static_assert(sizeof(struct audit_trailer_prefix)==52,"complete audit prefix");
