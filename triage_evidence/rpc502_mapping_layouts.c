#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <pthread/qos.h>

struct observed_mapping_result {
    int32_t descriptor;
    uint8_t untouched_padding[4];
    const void *mapping;
    uint64_t encoded_size;
    uint64_t opaque_auxiliary;
};

/* Epoch-specific prefix: this stack address is reused for other records. */
struct observed_file_helper_prefix {
    uint8_t unknown_prefix[0x18];
    const char *constructed_path;
    struct observed_mapping_result *result;
    uint32_t encoded_status;
    uint8_t untouched_tail[4];
};

_Static_assert(PROT_READ==1,"observed mapping protection");
_Static_assert(MAP_PRIVATE==2,"observed mapping flags");
_Static_assert((uintptr_t)MAP_FAILED==UINTPTR_MAX,"64-bit failed mapping result");
_Static_assert(sizeof(size_t)==8 && sizeof(off_t)==8,"mapping argument widths");
_Static_assert(sizeof(struct observed_mapping_result)==32,"result prefix extent");
_Static_assert(offsetof(struct observed_mapping_result,mapping)==8,"mapping output offset");
_Static_assert(offsetof(struct observed_mapping_result,encoded_size)==16,"encoded size output offset");
_Static_assert(offsetof(struct observed_mapping_result,opaque_auxiliary)==24,"opaque output offset");
_Static_assert(sizeof(struct observed_file_helper_prefix)==48,"helper record prefix extent");
_Static_assert(offsetof(struct observed_file_helper_prefix,constructed_path)==24,"path input offset");
_Static_assert(offsetof(struct observed_file_helper_prefix,result)==32,"result pointer input offset");
_Static_assert(offsetof(struct observed_file_helper_prefix,encoded_status)==40,"encoded status output offset");
_Static_assert(sizeof(qos_class_t)==4,"QoS class width");
_Static_assert(QOS_CLASS_USER_INTERACTIVE==0x21,"earlier class request");
typedef int (*qos_query_fn)(pthread_t,qos_class_t *,int *);
typedef int (*qos_set_fn)(qos_class_t,int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_get_qos_class_np),qos_query_fn),"SDK query prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_set_qos_class_self_np),qos_set_fn),"SDK setter prototype");
