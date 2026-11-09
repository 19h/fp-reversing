#include <mach/mach.h>
#include <mach/mig_errors.h>
#include <stddef.h>
#include <stdint.h>

/* User ABI uses installed SDK definitions. Kernel layouts are partial manual
 * records checked against original instructions, not exported SDK types. */
#pragma pack(push, 4)
struct user_port_request {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
};
struct user_status_reply { mach_msg_header_t header; NDR_record_t ndr; int32_t status; };
struct user_value_reply { struct user_status_reply base; uint32_t value; };
struct user_subscription_request {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t memory;
    NDR_record_t ndr;
    uint32_t count;
    uint64_t opaque;
};
struct partial_kernel_header { uint32_t bits, size; uint64_t remote, local; uint32_t voucher, id; };
struct partial_kernel_port { uint64_t object; uint16_t pad; uint8_t disposition, type; uint32_t pad2; };
struct partial_kernel_port_request { struct partial_kernel_header header; uint32_t count; struct partial_kernel_port port; };
struct partial_kernel_subscription_request {
    struct partial_kernel_header header;
    uint32_t descriptor_count;
    mach_msg_ool_descriptor_t memory;
    NDR_record_t ndr;
    uint32_t count;
    uint64_t opaque;
};
#pragma pack(pop)

_Static_assert(sizeof(mach_port_name_t)==4, "Mach names are u32");
_Static_assert(sizeof(mach_msg_header_t)==24, "user header");
_Static_assert(sizeof(struct user_port_request)==40, "MIG41471 and51471 user requests");
_Static_assert(offsetof(struct user_port_request,port)==28, "user port descriptor");
_Static_assert(sizeof(struct user_status_reply)==36, "MIG41571 and51571 user status");
_Static_assert(sizeof(struct user_value_reply)==40, "MIG61571 user success");
_Static_assert(sizeof(struct user_subscription_request)==64, "MIG61471 user request");
_Static_assert(offsetof(struct user_subscription_request,count)==52, "repeated count");
_Static_assert(offsetof(struct user_subscription_request,opaque)==56, "opaque scalar");
_Static_assert(sizeof(struct partial_kernel_header)==32, "observed internal header");
_Static_assert(sizeof(struct partial_kernel_port_request)==52, "observed internal41471 request");
_Static_assert(offsetof(struct partial_kernel_port_request,port.disposition)==46, "observed internal disposition");
_Static_assert(sizeof(struct partial_kernel_subscription_request)==72, "observed internal61471 request");
_Static_assert(MACH_MSG_TYPE_MOVE_SEND==17 && MACH_MSG_TYPE_COPY_SEND==19 && MACH_MSG_TYPE_MAKE_SEND==20, "right dispositions");
_Static_assert(MIG_TYPE_ERROR==-300 && MIG_REPLY_MISMATCH==-301 && MIG_SERVER_DIED==-308, "MIG statuses");
