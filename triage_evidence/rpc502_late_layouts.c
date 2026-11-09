#include <stddef.h>
#include <stdint.h>
struct bigint_view { uint32_t capacity,biased_signed_count;uint32_t *encoded_limbs; };
struct public_operation_view { uint64_t unknown0;const struct bigint_view *exponent;uint32_t result,unknown20;uint64_t unknown24;const struct bigint_view *modulus;uint32_t *exported_extent;uint32_t controls48,controls52;uint8_t *encoded_output;const uint8_t *signature_input;uint32_t controls72,controls76; };
_Static_assert(sizeof(struct public_operation_view)==80,"selected source-built prefix");
_Static_assert(offsetof(struct public_operation_view,exponent)==8,"exponent");
_Static_assert(offsetof(struct public_operation_view,result)==16,"result");
_Static_assert(offsetof(struct public_operation_view,modulus)==32,"modulus");
_Static_assert(offsetof(struct public_operation_view,exported_extent)==40,"extent pointer");
_Static_assert(offsetof(struct public_operation_view,encoded_output)==56,"output bytes");
_Static_assert(offsetof(struct public_operation_view,signature_input)==64,"input bytes");
uint32_t selected_result(const struct public_operation_view *p){return p->result;}
