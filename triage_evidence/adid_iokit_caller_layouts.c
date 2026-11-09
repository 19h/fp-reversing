/* Analyst declarations: compile only; no target/library invocation. */
#include <IOKit/IOKitLib.h>
#include <stdint.h>
#include <stddef.h>
struct primary_caller_prefix {
    uint64_t encoded_output_pointer;
    uint32_t encoded_basis;
    uint32_t status;
};
struct avp100_caller_prefix {
    uint64_t encoded_count_pointer;
    uint32_t encoded_size;
    uint32_t opaque;
    uint64_t destination;
    uint64_t inout_buffer;
    uint32_t status;
    uint32_t encoded_basis;
};
_Static_assert(sizeof(struct primary_caller_prefix)==16, "primary known prefix");
_Static_assert(sizeof(struct avp100_caller_prefix)==40, "Avp known prefix");
_Static_assert(offsetof(struct avp100_caller_prefix,status)==32, "Avp status");
_Static_assert(offsetof(struct avp100_caller_prefix,encoded_basis)==36, "Avp basis");
_Static_assert(sizeof(size_t)==8 && sizeof(io_connect_t)==4, "IOKit widths");
kern_return_t analyst_method100(io_connect_t c, void *p, size_t n, size_t *out) {
    return IOConnectCallStructMethod(c, 100, p, n, p, out);
}
