#include <stdint.h>
#include <stddef.h>
/* Analytical view of accesses only. Total target object size is unknown. */
struct supplemental_accessed_view {
 uint32_t field0,field4,field8,prior12;
 uint64_t mapping;
 uint32_t cursor_encoded,tail_parameter_encoded,status_encoded,body_length_encoded,field40;
};
_Static_assert(offsetof(struct supplemental_accessed_view,mapping)==16,"mapping at16");
_Static_assert(offsetof(struct supplemental_accessed_view,cursor_encoded)==24,"cursor at24");
_Static_assert(offsetof(struct supplemental_accessed_view,tail_parameter_encoded)==28,"parameter at28");
_Static_assert(offsetof(struct supplemental_accessed_view,status_encoded)==32,"status at32");
_Static_assert(offsetof(struct supplemental_accessed_view,body_length_encoded)==36,"length at36");
_Static_assert(offsetof(struct supplemental_accessed_view,field40)+sizeof(uint32_t)==44,"accessed prefix ends44");
_Static_assert(sizeof(struct supplemental_accessed_view)==48,"SDK C view includes trailing alignment padding");
uint32_t supplemental_address_key(uintptr_t p) { return ((uint32_t)p^0xc6d66014U)*0x6b86592fU; }
