/* Analyst ABI model; compile only, never link or invoke target APIs. */
#include <IOKit/IOKitLib.h>
#include <stdint.h>
#include <stddef.h>
struct adid_descriptor { uint64_t address; uint32_t extent; uint32_t trailing; };
_Static_assert(sizeof(mach_port_t) == 4, "Mach name width");
_Static_assert(sizeof(io_connect_t) == 4 && sizeof(io_iterator_t) == 4, "IOKit name widths");
_Static_assert(sizeof(kern_return_t) == 4, "status width");
_Static_assert(sizeof(size_t) == 8, "extent cell width");
_Static_assert(sizeof(struct adid_descriptor) == 16, "indirect structure extent");
_Static_assert(offsetof(struct adid_descriptor, extent) == 8, "pointed extent offset");
_Static_assert(offsetof(struct adid_descriptor, trailing) == 12, "trailing word offset");
_Static_assert(kIOReturnUnsupported == (IOReturn)0xe00002c7, "error fixture");
kern_return_t analyst_main(mach_port_t *out) { return IOMainPort(MACH_PORT_NULL, out); }
kern_return_t analyst_open(io_service_t service, task_port_t task, io_connect_t *out) {
    return IOServiceOpen(service, task, 0, out);
}
kern_return_t analyst_indirect(io_connect_t connection, struct adid_descriptor *d, size_t *n) {
    return IOConnectCallStructMethod(connection, 26, d, 16, d, n);
}
kern_return_t analyst_direct(io_connect_t connection, void *p, size_t *n) {
    return IOConnectCallStructMethod(connection, 26, p, 96, p, n);
}
