#include <IOKit/IOKitLib.h>
#include <mach/mach_init.h>
_Static_assert(sizeof(mach_port_t)==4,"mach_port_t32");
_Static_assert(sizeof(task_port_t)==4,"task_port_t32");
_Static_assert(sizeof(io_object_t)==4,"io_object_t32");
_Static_assert(sizeof(io_iterator_t)==4,"io_iterator_t32");
_Static_assert(sizeof(io_service_t)==4,"io_service_t32");
_Static_assert(sizeof(io_connect_t)==4,"io_connect_t32");
_Static_assert(sizeof(kern_return_t)==4,"kern_return_t32");
_Static_assert(sizeof(CFDictionaryRef)==8,"CFDictionaryRef64");
static kern_return_t (*matching_contract)(mach_port_t,CFDictionaryRef,io_iterator_t*) = IOServiceGetMatchingServices;
static io_object_t (*next_contract)(io_iterator_t) = IOIteratorNext;
static kern_return_t (*open_contract)(io_service_t,task_port_t,uint32_t,io_connect_t*) = IOServiceOpen;
static kern_return_t (*release_contract)(io_object_t) = IOObjectRelease;
