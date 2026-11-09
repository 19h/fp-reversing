#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
struct source_arena_descriptor_view {uint64_t unknown0,arena;uint32_t word16,word20;uint64_t unknown24;uint32_t word32,word36;uint64_t word40,word48,word56,word64,list_link72,word80;};
_Static_assert(sizeof(pthread_rwlock_t)==200,"SDK opaque lock200");
_Static_assert(sizeof(struct timeval)==16,"SDK timeval16");
_Static_assert(offsetof(struct timeval,tv_sec)==0,"sec0");
_Static_assert(offsetof(struct timeval,tv_usec)==8,"usec8");
_Static_assert(sizeof(((struct timeval*)0)->tv_sec)==8,"sec64");
_Static_assert(sizeof(((struct timeval*)0)->tv_usec)==4,"usec32");
_Static_assert(sizeof(size_t)==8,"malloc size64");
_Static_assert(sizeof(arc4random())==4,"entropy32");
_Static_assert(offsetof(struct source_arena_descriptor_view,arena)==8,"arena8");
_Static_assert(offsetof(struct source_arena_descriptor_view,list_link72)==72,"link72");
_Static_assert(offsetof(struct source_arena_descriptor_view,word80)==80,"word80");
void (*callback_type(void (*p)(void)))(void){return p;}
uint32_t decode_status(uint32_t x){return x^UINT32_C(0x8b3dc651);}
