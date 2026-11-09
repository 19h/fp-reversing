#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/ndr.h>
struct vm_request48 {
    mach_msg_header_t head;
    NDR_record_t ndr;
    mach_vm_address_t address;
    mach_vm_size_t size;
};
struct vm_reply36 { mach_msg_header_t head; NDR_record_t ndr; kern_return_t code; };
struct trap_args24 { mach_port_t name; uint32_t pad; uint64_t address, size; };
_Static_assert(sizeof(struct vm_request48) == 48, "request");
_Static_assert(offsetof(struct vm_request48, address) == 32, "address");
_Static_assert(offsetof(struct vm_request48, size) == 40, "size");
_Static_assert(sizeof(struct vm_reply36) == 36, "reply");
_Static_assert(sizeof(mach_msg_trailer_t) == 8, "base trailer");
_Static_assert(sizeof(struct trap_args24) == 24, "trap args");
_Static_assert(offsetof(struct trap_args24, address) == 8, "trap address");
_Static_assert(MACH_MSG_TYPE_COPY_SEND == 19, "remote disposition");
_Static_assert(MACH_MSG_TYPE_MAKE_SEND_ONCE == 21, "local disposition");
_Static_assert(MACH_SEND_INVALID_DEST == 0x10000003, "fallback code");
uint64_t packed_names(mach_port_t remote, mach_port_t local) {
    return (uint64_t)remote | ((uint64_t)local << 32);
}
