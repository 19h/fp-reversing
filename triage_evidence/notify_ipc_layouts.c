#include <stdint.h>
#include <stddef.h>
#include <mach/message.h>
#include <mach/mig.h>
#include <mach/ndr.h>
#include <notify.h>
#include <mach/notify.h>
#include <mach/port.h>
_Static_assert(MACH_NOTIFY_SEND_POSSIBLE==66,"send possible id66");
_Static_assert(MACH_MSG_TYPE_COPY_SEND==19,"copy send19");
_Static_assert(MACH_MSG_TYPE_MAKE_SEND==20,"make send20");
_Static_assert(MACH_MSG_TYPE_MAKE_SEND_ONCE==21,"make send once21");
_Static_assert(MPO_QLIMIT==2,"queue limit flag2");
_Static_assert(sizeof(mach_port_options_t)==24,"options24");
_Static_assert(offsetof(mach_port_options_t,mpl)==4,"port limits4");
_Static_assert(MACH_SEND_NOTIFY==0x80,"arm send possible flag80");
_Static_assert(MACH_SEND_TIMEOUT==0x10,"timeout flag10");
_Static_assert(MACH_SEND_TIMED_OUT==0x10000004,"send timed out result");
_Static_assert(sizeof(mach_port_t)==4,"Mach port name32");
_Static_assert(sizeof(mach_msg_header_t)==24,"header24");
_Static_assert(offsetof(mach_msg_header_t,msgh_id)==20,"message id20");
_Static_assert(sizeof(mach_msg_audit_trailer_t)==52,"audit trailer52");
_Static_assert(offsetof(mach_msg_audit_trailer_t,msgh_audit)==20,"audit token20");
_Static_assert(sizeof(audit_token_t)==32,"audit32");
_Static_assert(sizeof(NDR_record_t)==8,"NDR8");
_Static_assert(sizeof(struct routine_descriptor)==40,"MIG stride40");
_Static_assert(offsetof(struct routine_descriptor,stub_routine)==8,"stub8");
_Static_assert(offsetof(struct routine_descriptor,max_reply_msg)==32,"max reply32");
_Static_assert(offsetof(struct mig_subsystem,routine)==32,"routines32");
#pragma pack(push,4)
struct checkin_reply { mach_msg_header_t header; NDR_record_t ndr; int32_t kernel_status; uint32_t version,pid,status; };
struct register_check_reply { mach_msg_header_t header; NDR_record_t ndr; int32_t kernel_status; uint32_t shm_size,slot; uint64_t name_id; uint32_t status; };
struct cached_post { mach_msg_header_t header; NDR_record_t ndr; uint64_t name_id; uint32_t flags; };
struct cancel_request { mach_msg_header_t header; NDR_record_t ndr; uint32_t token; };
struct check_reply { mach_msg_header_t header; NDR_record_t ndr; int32_t kernel_status; uint32_t changed,status; };
#pragma pack(pop)
_Static_assert(sizeof(struct checkin_reply)==48,"checkin reply48");
_Static_assert(sizeof(struct register_check_reply)==56,"registration reply56");
_Static_assert(offsetof(struct register_check_reply,name_id)==44,"unaligned name id44");
_Static_assert(sizeof(struct cached_post)==44,"post44");
_Static_assert(sizeof(struct cancel_request)==36,"cancel36");
_Static_assert(sizeof(struct check_reply)==44,"check reply44");
uint32_t notify_contract(const char *name,int *token,int *changed) { return notify_register_check(name,token)|notify_check(*token,changed); }
