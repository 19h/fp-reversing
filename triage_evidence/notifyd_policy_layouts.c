#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
_Static_assert(sizeof(struct stat)==144,"stat144");
_Static_assert(offsetof(struct stat,st_mode)==4,"mode16 at4");
_Static_assert(sizeof(((struct stat*)0)->st_mode)==2,"mode16");
_Static_assert(offsetof(struct stat,st_uid)==16,"uid32 at16");
_Static_assert(offsetof(struct stat,st_gid)==20,"gid32 at20");
_Static_assert(offsetof(struct stat,st_size)==96,"size64 at96");
_Static_assert(S_IWOTH==2,"other write bit1");
_Static_assert(S_IWGRP==16,"group write bit4");
uint32_t source_access(uint32_t mask,uint32_t op,uint32_t uid,uint32_t gid,uint32_t owner,uint32_t group) {
 return ((uid==owner && (mask&op)) || (gid==group && (mask&(op<<4))) || (mask&(op<<8)));
}
#include <bsm/libbsm.h>
#include <mach/message.h>
#include <mach/ndr.h>
#pragma pack(push,4)
struct state_get_request { mach_msg_header_t header; NDR_record_t ndr; uint64_t name_id; };
struct state_get_reply { mach_msg_header_t header; NDR_record_t ndr; int32_t kernel_status; uint64_t state; uint32_t status; };
struct state_set_request { mach_msg_header_t header; NDR_record_t ndr; uint64_t name_id,state; uint32_t flags; };
#pragma pack(pop)
_Static_assert(sizeof(struct state_get_request)==40,"get request40");
_Static_assert(sizeof(struct state_get_reply)==48,"get reply48");
_Static_assert(offsetof(struct state_get_reply,state)==36,"unaligned state64 at36");
_Static_assert(sizeof(struct state_set_request)==52,"set request52");
_Static_assert(offsetof(struct state_set_request,flags)==48,"flags32 at48");
uint32_t audit_by_value_shape(audit_token_t token) { return audit_token_to_euid(token); }
