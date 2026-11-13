#define _DARWIN_C_SOURCE 1
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <unistd.h>
#include <pthread.h>

/* Compile-only current SDK comparison; historical runtime identity unknown. */
_Static_assert(sizeof(void *)==8 && sizeof(int)==4,"LP64 integer ABI");
_Static_assert(sizeof(struct stat)==144,"opaque stat extent");
_Static_assert(offsetof(struct stat,st_mode)==4,"mode offset");
_Static_assert(sizeof(((struct stat *)0)->st_mode)==2,"mode width");
_Static_assert(S_IFMT==0xf000 && S_IFLNK==0xa000,"link type constants");
_Static_assert(ENOENT==2,"missing path constant");
_Static_assert(sizeof(pthread_once_t)==16,"opaque once extent");
_Static_assert(sizeof(pthread_rwlock_t)==200,"opaque lock extent");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lstat),int(*)(const char *,struct stat *)),"lstat prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unlink),int(*)(const char *)),"unlink prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__error),int *(*)(void)),"errno accessor prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_once),int(*)(pthread_once_t *,void(*)(void))),"once prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_wrlock),int(*)(pthread_rwlock_t *)),"write lock prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock),int(*)(pthread_rwlock_t *)),"unlock prototype");

int removal_probe(const char *path) { return unlink(path); }
