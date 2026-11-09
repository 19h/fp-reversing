#include <stdint.h>
#include <stddef.h>
#include <mach/message.h>
#include <mach/ndr.h>
#include <mach/mig_errors.h>
struct request_user64 { mach_msg_header_t header; mach_msg_body_t body; mach_msg_ool_descriptor_t filename; NDR_record_t ndr; uint32_t repeated_extent; uint64_t cpu, subtype, origin; };
struct __attribute__((packed,aligned(4))) descriptor_kernel { uint64_t copy; uint32_t flags, extent; };
struct request_kernel { uint32_t bits, size; uint64_t remote, local; uint32_t voucher, id, count; struct descriptor_kernel filename; NDR_record_t ndr; uint32_t repeated_extent; uint64_t cpu, subtype, origin; };
_Static_assert(sizeof(struct request_user64)==80,"user request");
_Static_assert(sizeof(struct request_kernel)==88,"kernel request");
_Static_assert(offsetof(struct request_kernel,filename)==36,"kernel descriptor");
_Static_assert(offsetof(struct request_user64,filename)==28,"user descriptor");
_Static_assert(offsetof(struct request_user64,repeated_extent)==52,"repeated extent");
_Static_assert(offsetof(struct request_user64,cpu)==56,"CPU field");
_Static_assert(MACH_MSG_OOL_DESCRIPTOR==1,"descriptor type");
_Static_assert(MACH_MSG_VIRTUAL_COPY==1,"copy method");
_Static_assert(MIG_TYPE_ERROR==-300,"descriptor mismatch");
_Static_assert(MIG_BAD_ARGUMENTS==-304,"framing mismatch");
uint32_t received_size(struct request_user64 *r) { return r->header.msgh_size; }
