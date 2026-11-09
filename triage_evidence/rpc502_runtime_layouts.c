#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <fcntl.h>

/* Compiler-only current-SDK ABI context; no host synchronization or loading. */
_Static_assert(sizeof(pthread_once_t)==16,"LP64 once object");
_Static_assert(sizeof(pthread_rwlock_t)==200,"LP64 read/write lock object");
_Static_assert(offsetof(pthread_once_t,__opaque)==8,"opaque once payload");
_Static_assert(_PTHREAD_ONCE_SIG_init==0x30b1bcba,"once initializer signature");
_Static_assert((RTLD_LAZY|RTLD_LOCAL)==5,"loader flags");
_Static_assert(O_RDONLY==0,"read-only open flags");

struct coreke_three_argument_record {
    uint64_t operation_value;
    uint64_t third_argument;
    uint32_t first_argument;
    uint32_t second_argument;
};
struct coreke_one_argument_record {
    uint64_t operation_value;
    uint64_t first_argument;
};
struct encoded_runtime_comparison_frame {
    uint32_t field00,field04,field08,padding0c;
    uint64_t operand10;
    uint32_t field18,padding1c;
    uint64_t operand20;
    uint64_t encoded_leaf28;
    uint32_t field30,result34;
};
_Static_assert(sizeof(struct coreke_three_argument_record)==24,"three-argument wrapper prefix");
_Static_assert(offsetof(struct coreke_three_argument_record,first_argument)==0x10,"W0 slot");
_Static_assert(offsetof(struct coreke_three_argument_record,second_argument)==0x14,"W1 slot");
_Static_assert(sizeof(struct coreke_one_argument_record)==16,"one-argument wrapper prefix");
_Static_assert(sizeof(struct encoded_runtime_comparison_frame)==56,"runtime comparator prefix");
_Static_assert(offsetof(struct encoded_runtime_comparison_frame,result34)==0x34,"comparison result index");
