#define _DARWIN_C_SOURCE 1
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <pthread.h>

/* Compile-only current SDK comparison; historical runtime ABI is a premise. */
_Static_assert(sizeof(void *)==8 && sizeof(int)==4,"LP64 integer ABI");
_Static_assert(sizeof(struct stat)==144,"stat output extent");
_Static_assert(offsetof(struct stat,st_mode)==4,"mode offset");
_Static_assert(sizeof(((struct stat *)0)->st_mode)==2,"mode width");
_Static_assert(S_IFMT==0xf000 && S_IFLNK==0xa000,"mode classification");
_Static_assert(ENOENT==2,"missing pathname status");
_Static_assert(sizeof(pthread_once_t)==16,"once control extent");
_Static_assert(sizeof(pthread_rwlock_t)==200,"lock owner extent");
_Static_assert(O_RDONLY==0 && O_SHLOCK==0x10 && O_NOFOLLOW==0x100,"open flags");
_Static_assert((O_RDONLY|O_SHLOCK|O_NOFOLLOW)==0x110,"observed flag union");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lstat),int(*)(const char *,struct stat *)),"lstat prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&open),int(*)(const char *,int,...)),"open prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_once),int(*)(pthread_once_t *,void(*)(void))),"once prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_rdlock),int(*)(pthread_rwlock_t *)),"read lock prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock),int(*)(pthread_rwlock_t *)),"unlock prototype");

int admission_open_probe(const char *path) {
    return open(path,O_RDONLY|O_SHLOCK|O_NOFOLLOW,0);
}
