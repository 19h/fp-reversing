#include <IOKit/IOBufferMemoryDescriptor.h>
static_assert(kIODirectionNone == 0);
static_assert(kIODirectionInOut == 3);
static_assert(kIOMemoryPhysicallyContiguous == 0x10);
static_assert((kIODirectionInOut | kIOMemoryPhysicallyContiguous) == 0x13);
static_assert(kIOMemoryKernelUserShared == 0x10000);
static_assert((0x13 & kIOMemoryKernelUserShared) == 0);
static_assert(sizeof(IOOptionBits) == 4);
static_assert(sizeof(IOByteCount) == 8);
