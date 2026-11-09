#include <IOKit/IOLib.h>
static_assert(sizeof(vm_size_t) == 8, "SDK allocation extent width");
extern "C" void *probe_data_alloc(vm_size_t size) { return IOMallocData(size); }
extern "C" void probe_data_free(void *pointer, vm_size_t size) { IOFreeData(pointer, size); }
