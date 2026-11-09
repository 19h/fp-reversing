#include <stdint.h>
#include <stddef.h>
#include <mach/message.h>
/* Reconstructed field views; not original private kernel typedefs. */
struct receiver_view { uint8_t gap[0x388]; uint32_t limit, aux_limit; uint64_t options, object; uint32_t state, sequence, size, aux_size, name, pad; uint64_t message; };
struct accounting_view { uint8_t gap[0x3d8]; uint64_t received_counter; };
_Static_assert(offsetof(struct receiver_view,state)==0x3a0,"receive state");
_Static_assert(offsetof(struct receiver_view,sequence)==0x3a4,"sequence");
_Static_assert(offsetof(struct receiver_view,message)==0x3b8,"message");
_Static_assert(offsetof(struct accounting_view,received_counter)==0x3d8,"receive counter base");
_Static_assert(MACH_RCV_TIMEOUT==0x100,"receive timeout option");
_Static_assert(MACH_RCV_LARGE==4,"large receive option");
_Static_assert(MACH_RCV_TIMED_OUT==0x10004003,"timeout state");
_Static_assert(MACH_RCV_INTERRUPTED==0x10004005,"interrupted state");
_Static_assert(MACH_RCV_PORT_CHANGED==0x10004006,"port-changed restart state");
_Static_assert(MACH_RCV_TOO_LARGE==0x10004004,"large state");
uint32_t next_sequence(uint32_t sequence) { return sequence+1; }
