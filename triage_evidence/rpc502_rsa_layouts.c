#include <stddef.h>
#include <stdint.h>
struct bigint_view { uint32_t capacity,biased_signed_count;uint32_t *encoded_limbs; };
struct mont_context_view { struct bigint_view *radix,*precomputation;uint32_t n0prime,padding_unknown; };
struct square_view { struct mont_context_view *context;uint32_t add_mode,padding_unknown;struct bigint_view *output,*operand,*modulus; };
struct product_view { struct mont_context_view *context;struct bigint_view *modulus,*output,*left;uint32_t xor_mode,padding_unknown;struct bigint_view *right; };
struct cert_key_view { unsigned char unknown0[0x210];struct bigint_view modulus;unsigned char unknown1[0x100];struct bigint_view exponent; };
_Static_assert(sizeof(struct bigint_view)==16,"bigint selected extent");
_Static_assert(offsetof(struct bigint_view,encoded_limbs)==8,"limb pointer");
_Static_assert(sizeof(struct mont_context_view)==24,"context selected extent");
_Static_assert(sizeof(struct square_view)==40,"square selected extent");
_Static_assert(offsetof(struct square_view,output)==16,"square output");
_Static_assert(offsetof(struct square_view,modulus)==32,"square modulus");
_Static_assert(sizeof(struct product_view)==48,"product selected extent");
_Static_assert(offsetof(struct product_view,right)==40,"product right");
_Static_assert(offsetof(struct product_view,xor_mode)==32,"product mode");
_Static_assert(offsetof(struct cert_key_view,exponent)==0x320,"certificate exponent");
uint32_t selected_montgomery_constant(const struct mont_context_view *p){return p->n0prime;}
