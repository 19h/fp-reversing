#include <stdint.h>
#include <stddef.h>
struct source_name_record {
 uintptr_t client_head;
 uintptr_t string_pointer;
 uint64_t name_id;
 uint64_t opaque18;
 uint64_t opaque20;
 uint32_t opaque28,opaque2c;
 uint32_t access_word,shared_slot;
 uint32_t client_count,generation;
 uint32_t retain_word,opaque44;
 unsigned char inline_name[];
};
struct source_client_record {
 uintptr_t next0,previous8,next10,previous18;
 uint64_t opaque20,opaque28;
 uintptr_t name_record;
 uint64_t opaque38;
 uint64_t pid_token_key;
 uint32_t last_generation;
 uint16_t auxiliary_index;
 uint8_t suspend_count,delivery_flags;
 uint64_t opaque50;
};
_Static_assert(sizeof(uintptr_t)==8,"source ptr64");
_Static_assert(sizeof(struct source_name_record)==72,"name fixed72");
_Static_assert(offsetof(struct source_name_record,string_pointer)==8,"name pointer8");
_Static_assert(offsetof(struct source_name_record,name_id)==16,"name ID16");
_Static_assert(offsetof(struct source_name_record,shared_slot)==52,"slot52");
_Static_assert(offsetof(struct source_name_record,generation)==60,"generation60");
_Static_assert(offsetof(struct source_name_record,inline_name)==72,"inline name72");
_Static_assert(sizeof(struct source_client_record)==88,"client allocation88");
_Static_assert(offsetof(struct source_client_record,name_record)==48,"client name48");
_Static_assert(offsetof(struct source_client_record,pid_token_key)==64,"PID-token key64");
_Static_assert(offsetof(struct source_client_record,last_generation)==72,"sample72");
_Static_assert(offsetof(struct source_client_record,delivery_flags)==79,"flags79");
uint64_t key_contract(uint32_t pid,uint32_t token) { return ((uint64_t)pid<<32)|token; }
