#include <stddef.h>
#include <stdint.h>
struct policy_carrier_view { uint32_t xor_kind,unknown4,xor_extent,unknown12;const void *mapping;uint32_t xor_cursor,add_parameter,xor_status,add_body_size,add_auxiliary; };
_Static_assert(offsetof(struct policy_carrier_view,xor_extent)==8,"extent field");
_Static_assert(offsetof(struct policy_carrier_view,mapping)==16,"mapped pointer");
_Static_assert(offsetof(struct policy_carrier_view,add_parameter)==28,"parameter");
_Static_assert(offsetof(struct policy_carrier_view,add_auxiliary)==40,"auxiliary");
_Static_assert(sizeof(struct policy_carrier_view)==48,"ABI trailing padding");
uint32_t selected_parameter(const struct policy_carrier_view *p,uint32_t key){return(p->add_parameter+key)^UINT32_C(0x8b3dc651);}
uint32_t selected_extent(const struct policy_carrier_view *p,uint32_t key){return(p->xor_extent^key)+UINT32_C(0xd51c85f8);}
