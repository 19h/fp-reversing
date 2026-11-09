typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;
#define OFF(T,F) __builtin_offsetof(T,F)
struct rpc502_private_prefix {
    u32 receiving_service, padding04;
    u64 filename, cpu_type, cpu_subtype, origin;
    u32 audit[8];
    u64 fixed_record0_destination, fixed_record1_destination;
    u64 ool0_address;
    u32 ool0_extent, padding64;
    u64 ool1_address;
    u32 ool1_extent, padding74;
};
_Static_assert(OFF(struct rpc502_private_prefix,filename)==8,"filename");
_Static_assert(OFF(struct rpc502_private_prefix,cpu_type)==0x10,"CPU");
_Static_assert(OFF(struct rpc502_private_prefix,origin)==0x20,"origin");
_Static_assert(OFF(struct rpc502_private_prefix,audit)==0x28,"audit value copy");
_Static_assert(OFF(struct rpc502_private_prefix,fixed_record0_destination)==0x48,"fixed0");
_Static_assert(OFF(struct rpc502_private_prefix,fixed_record1_destination)==0x50,"fixed1");
_Static_assert(OFF(struct rpc502_private_prefix,ool0_address)==0x58,"OOL0 VA");
_Static_assert(OFF(struct rpc502_private_prefix,ool0_extent)==0x60,"OOL0 count");
_Static_assert(OFF(struct rpc502_private_prefix,ool1_address)==0x68,"OOL1 VA");
_Static_assert(OFF(struct rpc502_private_prefix,ool1_extent)==0x70,"OOL1 count");
_Static_assert(sizeof(struct rpc502_private_prefix)==0x78,"partial record bytes");
