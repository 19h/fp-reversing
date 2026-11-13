#define _DARWIN_C_SOURCE 1
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <pthread.h>

/* Compile-only current arm64e comparison, not a historical runtime claim. */
_Static_assert(sizeof(void *)==8 && sizeof(size_t)==8 && sizeof(int)==4,"LP64 ABI");
_Static_assert(sizeof(struct stat)==144,"stat output span");
_Static_assert(offsetof(struct stat,st_mode)==4,"mode offset");
_Static_assert(sizeof(((struct stat *)0)->st_mode)==2,"mode width");
_Static_assert(S_IFMT==0xf000 && S_IFLNK==0xa000 && ENOENT==2,"metadata constants");
_Static_assert(sizeof(pthread_once_t)==16 && sizeof(pthread_rwlock_t)==200,"opaque synchronization spans");
_Static_assert(__builtin_types_compatible_p(__typeof__(&malloc),void *(*)(size_t)),"malloc prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&free),void(*)(void *)),"free prototype");

void retirement_probe(void *p) { free(p); }
void *construction_probe(void) { return malloc(64); }
