#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <dispatch/dispatch.h>
#include <bsm/libbsm.h>
struct source_block_header { void *isa; uint32_t flags,reserved; void *invoke,*descriptor; };
struct source_block_capture { struct source_block_header h; void *record; };
struct source_block_config_post { struct source_block_capture h; uint32_t uid,gid; };
#pragma pack(push,4)
struct source_block_fd_capture { struct source_block_header h; int32_t fd; };
#pragma pack(pop)
struct source_monitor_record { char *path; uint64_t capacity; audit_token_t audit; uint32_t component_count,unknown_34; char **components; uint32_t status,flags; void *source; char *name; uint64_t unknown_58,client_key; uint32_t refs,unknown_6c; };
struct source_watcher_record { char *path; uint32_t follow; int32_t fd; struct timespec mtime,ctime; void *source; uint32_t monitor_count,unknown_3c; struct source_monitor_record **monitors; };
_Static_assert(sizeof(struct source_block_header)==32,"block header32");
_Static_assert(sizeof(struct source_block_capture)==40,"capture40");
_Static_assert(sizeof(struct source_block_config_post)==48,"config post48");
_Static_assert(sizeof(struct source_block_fd_capture)==36,"FD capture36");
_Static_assert(sizeof(struct source_monitor_record)==112,"source allocation112");
_Static_assert(offsetof(struct source_monitor_record,audit)==16,"audit at10");
_Static_assert(offsetof(struct source_monitor_record,components)==56,"components at38");
_Static_assert(offsetof(struct source_monitor_record,flags)==68,"flags at44");
_Static_assert(offsetof(struct source_monitor_record,source)==72,"source at48");
_Static_assert(offsetof(struct source_monitor_record,client_key)==96,"key at60");
_Static_assert(offsetof(struct source_monitor_record,refs)==104,"refs at68");
_Static_assert(sizeof(struct source_watcher_record)==72,"watcher allocation72");
_Static_assert(offsetof(struct source_watcher_record,mtime)==16,"watcher mtime10");
_Static_assert(offsetof(struct source_watcher_record,ctime)==32,"watcher ctime20");
_Static_assert(offsetof(struct source_watcher_record,source)==48,"watcher source30");
_Static_assert(offsetof(struct source_watcher_record,monitors)==64,"watcher array40");
_Static_assert(sizeof(struct stat)==144,"stat144");
_Static_assert(offsetof(struct stat,st_mtimespec)==48,"stat mtime30");
_Static_assert(offsetof(struct stat,st_ctimespec)==64,"stat ctime40");
_Static_assert(sizeof(struct timespec)==16,"timespec16");
_Static_assert(O_EVTONLY==0x8000 && O_SYMLINK==0x200000,"open flags");
_Static_assert((NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_LINK|NOTE_RENAME|NOTE_REVOKE)==0x7f,"vnode mask7f");
_Static_assert(SYS_initgroups==243,"syscall243");
_Static_assert(NSEC_PER_SEC/10==100000000,"delay100ms");
uint32_t source_selected_mask(uint32_t mask,uint32_t event) { return mask&event&0x3ff; }
