#include <pthread.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
_Static_assert(sizeof(pthread_rwlock_t)==200,"rwlock extent");
_Static_assert(offsetof(pthread_rwlock_t,__sig)==0,"signature offset");
_Static_assert(offsetof(pthread_rwlock_t,__opaque)==8,"opaque offset");
_Static_assert(sizeof(void*)==8 && sizeof(int)==4,"ABI widths");
_Static_assert(ENOMEM==12 && EBUSY==16,"status constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_init),int(*)(pthread_rwlock_t*,const pthread_rwlockattr_t*)),"initializer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&malloc),void*(*)(size_t)),"allocator ABI");
const pthread_rwlock_t recovered_static_rwlock=PTHREAD_RWLOCK_INITIALIZER;
