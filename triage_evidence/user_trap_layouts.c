#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <mach/message.h>
#include <mach/arm/vm_param.h>

struct observed_mach_vector {
    uint64_t data;
    uint64_t receive_address;
    uint32_t send_size;
    uint32_t receive_size;
};
struct observed_mach2_register_packet { uint64_t x[8]; };

_Static_assert(sizeof(mach_msg_header_t)==24,"user Mach header extent");
_Static_assert(offsetof(mach_msg_header_t,msgh_remote_port)==8,"remote name offset");
_Static_assert(offsetof(mach_msg_header_t,msgh_local_port)==12,"local name offset");
_Static_assert(offsetof(mach_msg_header_t,msgh_voucher_port)==16,"voucher name offset");
_Static_assert(offsetof(mach_msg_header_t,msgh_id)==20,"message ID offset");
_Static_assert(sizeof(mach_msg_body_t)==4,"complex descriptor-count prefix");
_Static_assert(sizeof(mach_port_name_t)==4 && sizeof(mach_msg_size_t)==4,"Mach scalar widths");
_Static_assert(sizeof(mach_msg_option_t)==4,"legacy option width");
_Static_assert(sizeof(struct observed_mach_vector)==24,"observed vector extent");
_Static_assert(offsetof(struct observed_mach_vector,send_size)==16,"vector size pair offset");
_Static_assert(sizeof(struct observed_mach2_register_packet)==64,"eight-register extent");
_Static_assert(MACH_SEND_MSG==1 && MACH_RCV_MSG==2,"operation bits");
_Static_assert(MACH_SEND_INTERRUPT==0x40 && MACH_RCV_INTERRUPT==0x400,"library interrupt flags");
_Static_assert(MACH_RCV_SYNC_WAIT==0x4000,"conditional receive-retry flag");
_Static_assert(MACH_SEND_INTERRUPTED==0x10000007 && MACH_RCV_INTERRUPTED==0x10004005,"retry statuses");
_Static_assert(MACH_SEND_INVALID_DEST==0x10000003 && MACH_SEND_TIMED_OUT==0x10000004,"daemon reply cleanup statuses");
_Static_assert(SWI_SYSCALL==0x80,"ARM64 SVC immediate");
_Static_assert(SYS_open==5 && SYS_close==6 && SYS_munmap==73,"BSD selectors");
_Static_assert(SYS_mmap==197 && SYS_fstat64==339,"BSD mapping/stat selectors");
_Static_assert(MAP_UNIX03==0x40000,"wrapper-added flag");
_Static_assert(sizeof(size_t)==8 && sizeof(off_t)==8 && sizeof(mode_t)==2,"BSD ABI widths");
typedef mach_msg_return_t (*legacy_msg_fn)(mach_msg_header_t *,mach_msg_option_t,
    mach_msg_size_t,mach_msg_size_t,mach_port_name_t,mach_msg_timeout_t,mach_port_name_t);
typedef mach_msg_return_t (*overwrite_msg_fn)(mach_msg_header_t *,mach_msg_option_t,
    mach_msg_size_t,mach_msg_size_t,mach_port_name_t,mach_msg_timeout_t,mach_port_name_t,
    mach_msg_header_t *,mach_msg_size_t);
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_msg),legacy_msg_fn),"legacy API prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_msg_overwrite),overwrite_msg_fn),"overwrite API prototype");
