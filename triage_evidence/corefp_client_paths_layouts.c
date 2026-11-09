/* Compile only;fields describe widths/offsets,not host integer order. */
#include <stdint.h>
#include <stddef.h>
#include <mach/message.h>
#pragma pack(push,1)
struct adid_request28 { uint32_t word0_be,word4_be,word8_be; uint64_t selector_be,opaque20_be; };
#pragma pack(pop)
_Static_assert(sizeof(struct adid_request28)==28,"28-byte wire record");
_Static_assert(offsetof(struct adid_request28,selector_be)==12,"64-bit selector at12");
_Static_assert(offsetof(struct adid_request28,opaque20_be)==20,"64-bit field at20");
_Static_assert(MACH_SEND_INVALID_DEST==0x10000003,"legacy lookup/retry trigger");
