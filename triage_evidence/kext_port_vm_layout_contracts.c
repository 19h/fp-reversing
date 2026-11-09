/* Native offset representations; these are partial views, not private types. */
typedef __UINT64_TYPE__ u64;
typedef __UINT32_TYPE__ u32;
typedef unsigned char u8;
#define OFF(T,F) __builtin_offsetof(T,F)
struct scratch_prefix {
    u8 unknown00[0x18];
    u64 destination_port;
    u8 unknown20[8];
    u64 request_vm_copy;
    u8 unknown30[0x10];
    u64 reply_vm_copy1;
    u8 unknown48[0x10];
    u64 fixed_record0;
    u8 unknown60[0x20];
    u64 ipc_staging_address;
    u8 unknown88[8];
    u64 reply_vm_copy0;
    u64 fixed_record1;
};
struct record0_modified_prefix {
    u8 earlier_fields[0x48];
    u64 mapped_address;
    u32 mapped_extent;
    u32 unknown54;
    u64 cleared58;
    u32 cleared60;
};
_Static_assert(OFF(struct scratch_prefix,destination_port)==0x18,"port");
_Static_assert(OFF(struct scratch_prefix,request_vm_copy)==0x28,"input copy");
_Static_assert(OFF(struct scratch_prefix,reply_vm_copy1)==0x40,"reply copy1");
_Static_assert(OFF(struct scratch_prefix,fixed_record0)==0x58,"fixed0");
_Static_assert(OFF(struct scratch_prefix,ipc_staging_address)==0x80,"staging");
_Static_assert(OFF(struct scratch_prefix,reply_vm_copy0)==0x90,"reply copy0");
_Static_assert(OFF(struct scratch_prefix,fixed_record1)==0x98,"fixed1");
_Static_assert(sizeof(struct scratch_prefix)==0xa0,"prefix size only");
_Static_assert(OFF(struct record0_modified_prefix,mapped_address)==0x48,"mapped VA");
_Static_assert(OFF(struct record0_modified_prefix,mapped_extent)==0x50,"mapped bytes");
_Static_assert(OFF(struct record0_modified_prefix,cleared58)==0x58,"clear qword");
_Static_assert(OFF(struct record0_modified_prefix,cleared60)==0x60,"clear word");
