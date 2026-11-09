#include <pthread.h>
#include <stdlib.h>
_Static_assert(sizeof(void *) == 8, "pointer width");
_Static_assert(sizeof(int) == 4, "int width");
_Static_assert(sizeof(pthread_once_t) == 16, "once owner extent");
_Static_assert(sizeof(pthread_rwlock_t) == 200, "rwlock owner extent");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_once), int (*)(pthread_once_t *, void (*)(void))), "once signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_wrlock), int (*)(pthread_rwlock_t *)), "write lock signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock), int (*)(pthread_rwlock_t *)), "unlock signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&free), void (*)(void *)), "free signature");

_Static_assert(sizeof(size_t) == 8, "size_t width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&malloc), void *(*)(size_t)), "malloc signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_init), int (*)(pthread_rwlock_t *, const pthread_rwlockattr_t *)), "init signature");
