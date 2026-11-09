/* Compile-only installed SDK ABI checks; no target APIs execute. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
_Static_assert(sizeof(uint32_t)==4,"u32 extent");
_Static_assert(sizeof(struct timeval)==16,"timeval extent");
_Static_assert(_Alignof(struct timeval)==8,"timeval alignment");
_Static_assert(offsetof(struct timeval,tv_sec)==0,"seconds offset");
_Static_assert(sizeof(((struct timeval*)0)->tv_sec)==8,"seconds extent");
_Static_assert(offsetof(struct timeval,tv_usec)==8,"microseconds offset");
_Static_assert(sizeof(((struct timeval*)0)->tv_usec)==4,"microseconds extent");
_Static_assert(__builtin_types_compatible_p(__typeof__(&arc4random),uint32_t(*)(void)),"entropy signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettimeofday),int(*)(struct timeval*restrict,void*restrict)),"time signature");
