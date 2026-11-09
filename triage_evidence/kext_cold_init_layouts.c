#include <mach/clock_types.h>
#include <stddef.h>
_Static_assert(sizeof(mach_timespec_t)==8,"timespec8");
_Static_assert(offsetof(mach_timespec_t,tv_sec)==0,"seconds0");
_Static_assert(offsetof(mach_timespec_t,tv_nsec)==4,"nanoseconds4");
_Static_assert(sizeof(((mach_timespec_t*)0)->tv_sec)==4,"seconds32");
_Static_assert(sizeof(((mach_timespec_t*)0)->tv_nsec)==4,"nanoseconds32");
_Static_assert((clock_res_t)-1<0,"signed nanoseconds");
