#include <IOKit/IOBufferMemoryDescriptor.h>
IOByteCount descriptor_read_probe(IOMemoryDescriptor *descriptor,
                                  IOByteCount offset, void *destination,
                                  IOByteCount length) {
    return descriptor->readBytes(offset, destination, length);
}
