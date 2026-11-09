typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;
#define OFF(T,F) __builtin_offsetof(T,F)
/* Observed encoded comparison prefix; names describe native accesses only. */
struct comparison_prefix {
    u32 encoded_kind, padding04;
    u64 encoded_value;
    u32 result_index, encoded_result_mask;
    u32 unused18, padding1c;
    u64 encoded_rhs;
    u32 false_index, true_index;
};
_Static_assert(OFF(struct comparison_prefix,encoded_value)==8,"value");
_Static_assert(OFF(struct comparison_prefix,result_index)==0x10,"index output");
_Static_assert(OFF(struct comparison_prefix,encoded_result_mask)==0x14,"result mask");
_Static_assert(OFF(struct comparison_prefix,encoded_rhs)==0x20,"rhs");
_Static_assert(OFF(struct comparison_prefix,false_index)==0x28,"false choice");
_Static_assert(OFF(struct comparison_prefix,true_index)==0x2c,"true choice");
_Static_assert(sizeof(struct comparison_prefix)==0x30,"prefix only");
