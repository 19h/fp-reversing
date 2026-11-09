#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
struct source_sidecar_record { uint32_t header_encoded; uint8_t opaque4[4]; uint32_t selector_encoded,optional_encoded[3]; uint8_t encoded_span[32]; };
_Static_assert(sizeof(struct source_sidecar_record)==56,"record56");
_Static_assert(offsetof(struct source_sidecar_record,opaque4)==4,"opaque4 at4");
_Static_assert(offsetof(struct source_sidecar_record,selector_encoded)==8,"selector32 at8");
_Static_assert(offsetof(struct source_sidecar_record,optional_encoded)==12,"three optional u32 at12");
_Static_assert(offsetof(struct source_sidecar_record,encoded_span)==24,"span32 at24");
_Static_assert(sizeof(int)==4,"int32 statuses and FDs");
_Static_assert(sizeof(size_t)==8,"size_t64");
uint8_t local_byte_codec(uint8_t x) { return (uint8_t)(x-((x<<1)&0x30)-0x68); }
