#include <stdint.h>
#include <stddef.h>
#include <mach/message.h>
#include <mach/ndr.h>
struct simple_reply { mach_msg_header_t header; NDR_record_t ndr; uint32_t result; };
/* Reconstructed receive-results view, not an original private typedef. */
struct result_view { uint32_t message_size, trailer_size, auxiliary_size, receiver_name, sequence, reserved; uint64_t context, metadata; };
_Static_assert(sizeof(mach_msg_header_t)==24,"user header");
_Static_assert(offsetof(mach_msg_header_t,msgh_remote_port)==8,"remote name");
_Static_assert(offsetof(mach_msg_header_t,msgh_local_port)==12,"local name");
_Static_assert(sizeof(struct simple_reply)==36,"simple reply");
_Static_assert(offsetof(mach_msg_audit_trailer_t,msgh_audit)==20,"audit offset");
_Static_assert(sizeof(mach_msg_audit_trailer_t)==52,"audit trailer");
_Static_assert(sizeof(struct result_view)==40,"receive result record");
_Static_assert(offsetof(struct result_view,context)==24,"context result");
_Static_assert(MACH_RCV_INVALID_DATA==0x10004008,"copyout failure status");
uint32_t converted_local_name(struct simple_reply *reply) { return reply->header.msgh_local_port; }
