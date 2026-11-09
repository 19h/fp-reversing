/* Compile only. No target or host API is called. */
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/message.h>
#include <mach/ndr.h>

struct corefp_version_output { uint32_t major, minor, patch; };
struct corefp_version_record {
    uint32_t status;
    uint32_t encoded_operation;
    struct corefp_version_output *output;
};
_Static_assert(sizeof(void *) == 8, "arm64e pointer ABI");
_Static_assert(sizeof(struct corefp_version_output) == 12, "three u32 version components");
_Static_assert(sizeof(struct corefp_version_record) == 16, "version helper record");
_Static_assert(offsetof(struct corefp_version_record, encoded_operation) == 4, "operation offset");
_Static_assert(offsetof(struct corefp_version_record, output) == 8, "output pointer offset");
_Static_assert(_SC_PAGESIZE == 29 && _SC_PAGE_SIZE == 29, "sysconf selector");
_Static_assert((PROT_READ | PROT_WRITE) == 3, "mapping protection");
_Static_assert((MAP_ANON | MAP_PRIVATE) == 0x1002, "mapping flags");
_Static_assert(sizeof(mach_msg_header_t) == 24, "userland Mach header");
_Static_assert(sizeof(mach_msg_ool_descriptor_t) == 16, "arm64e OOL descriptor");
_Static_assert(sizeof(NDR_record_t) == 8, "NDR byte extent");
_Static_assert(offsetof(mach_msg_header_t, msgh_remote_port) == 8, "remote port field");
_Static_assert(offsetof(mach_msg_header_t, msgh_local_port) == 12, "reply port field");
_Static_assert(offsetof(mach_msg_header_t, msgh_id) == 20, "message ID field");
_Static_assert(MACH_MSG_TYPE_COPY_SEND == 19 && MACH_MSG_TYPE_MAKE_SEND_ONCE == 21, "port dispositions");
_Static_assert(MACH_MSGH_BITS(19,21) == 0x1513, "header bits");
_Static_assert(MACH_MSGH_BITS_COMPLEX == 0x80000000U, "complex body bit");
_Static_assert((MACH_SEND_MSG | MACH_RCV_MSG) == 3, "send and receive options");
_Static_assert(MACH_MSG_OOL_DESCRIPTOR == 1 && MACH_MSG_VIRTUAL_COPY == 1, "OOL descriptor constants");
