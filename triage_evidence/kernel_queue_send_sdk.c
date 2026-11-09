#include <stdint.h>
#include <stddef.h>
#include <mach/message.h>
/* Reconstructed views only; no original private header provenance. */
struct queue_view { uint64_t head; uint32_t sequence, receiver_name; uint16_t count, limit; };
struct message_view { uint64_t next, previous; uint8_t gap[0x3e - 16], qos, storage; };
struct receiver_view { uint8_t prefix[0x388]; uint32_t limit, aux_limit; uint64_t options, unknown398; uint32_t state, sequence, message_size, aux_size, receiver_name, unknown3b4; uint64_t message; };
_Static_assert(offsetof(struct queue_view,sequence)==8,"queue sequence");
_Static_assert(offsetof(struct queue_view,count)==0x10,"reservation count");
_Static_assert(offsetof(struct queue_view,limit)==0x12,"limit");
_Static_assert(offsetof(struct message_view,qos)==0x3e,"QoS");
_Static_assert(offsetof(struct message_view,storage)==0x3f,"storage");
_Static_assert(offsetof(struct receiver_view,options)==0x390,"receive options");
_Static_assert(offsetof(struct receiver_view,state)==0x3a0,"receive state");
_Static_assert(offsetof(struct receiver_view,message)==0x3b8,"message handoff");
_Static_assert(MACH_SEND_TIMEOUT==0x10,"send timeout option");
_Static_assert(MACH_RCV_LARGE==4,"large receive option");
_Static_assert(MACH_MSG_TYPE_MOVE_SEND_ONCE==18,"send-once disposition");
_Static_assert(MACH_SEND_TIMED_OUT==0x10000004,"timeout status");
_Static_assert(MACH_SEND_INTERRUPTED==0x10000007,"interruption status");
_Static_assert(MACH_SEND_INVALID_DEST==0x10000003,"destination status");
_Static_assert(MACH_SEND_NO_BUFFER==0x1000000d,"buffer status");
_Static_assert(MACH_RCV_TOO_LARGE==0x10004004,"receive extent status");
uint32_t simple_copyout_size(uint32_t kernel_size) { return kernel_size-8; }
