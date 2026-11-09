#include <IOKit/IOMemoryDescriptor.h>
#include <stddef.h>
static_assert(sizeof(IOAddressRange) == 16);
static_assert(offsetof(IOAddressRange, address) == 0);
static_assert(offsetof(IOAddressRange, length) == 8);
static_assert(sizeof(((IOAddressRange *)0)->address) == 8);
static_assert(sizeof(((IOAddressRange *)0)->length) == 8);
static_assert(kIOMemoryTypeVirtual == 0x10);
static_assert(kIOMemoryTypePhysical == 0x20);
static_assert(kIODirectionOut == 2);
static_assert(kIODirectionInOut == 3);
static_assert(sizeof(IOByteCount) == 8);
IOByteCount sample_read_probe(IOMemoryDescriptor *d, IOByteCount o,
                             void *p, IOByteCount n) {
    return d->readBytes(o, p, n);
}
IOByteCount sample_write_probe(IOMemoryDescriptor *d, IOByteCount o,
                              const void *p, IOByteCount n) {
    return d->writeBytes(o, p, n);
}
