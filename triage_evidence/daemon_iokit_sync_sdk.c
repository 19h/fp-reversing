#include <pthread.h>
_Static_assert(sizeof(void *) == 8, "pointer width");
_Static_assert(sizeof(int) == 4, "return width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_once), int (*)(pthread_once_t *, void (*)(void))), "once signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_wrlock), int (*)(pthread_rwlock_t *)), "write-lock signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock), int (*)(pthread_rwlock_t *)), "unlock signature");
