#include <stdint.h>
#include <stddef.h>

/* Partial analyst layouts, established by original loads/stores. */
struct subscription_arguments {
    uint32_t service, pad0;
    uint64_t path;
    uint32_t transported_count, pad1;
    uint64_t opaque, decision_output;
};
struct partial_path_record {
    uint8_t unknown_prefix[56];
    uint64_t original_path;
    uint64_t unknown40;
    uint32_t encoded_inclusive_length, mode;
};
struct partial_global_block {
    uint64_t isa;
    uint32_t flags, reserved;
    uint64_t invoke, descriptor;
};
_Static_assert(sizeof(struct subscription_arguments)==40,"argument prefix");
_Static_assert(offsetof(struct subscription_arguments,transported_count)==16,"count offset");
_Static_assert(offsetof(struct subscription_arguments,opaque)==24,"opaque offset");
_Static_assert(offsetof(struct subscription_arguments,decision_output)==32,"decision pointer offset");
_Static_assert(sizeof(struct partial_path_record)==80,"private record");
_Static_assert(offsetof(struct partial_path_record,original_path)==56,"path offset");
_Static_assert(offsetof(struct partial_path_record,encoded_inclusive_length)==72,"length offset");
_Static_assert(sizeof(struct partial_global_block)==32,"block prefix");
_Static_assert(offsetof(struct partial_global_block,invoke)==16,"block invoke pointer");
