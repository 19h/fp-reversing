#include <IOKit/IOKitLib.h>
_Static_assert(sizeof(mach_port_t)==4,"mach_port_t32");
_Static_assert(sizeof(CFMutableDictionaryRef)==8,"dictionary_pointer64");
_Static_assert(sizeof(const char*)==8,"cstring_pointer64");
static kern_return_t (*main_contract)(mach_port_t,mach_port_t*) = IOMainPort;
static CFMutableDictionaryRef (*class_contract)(const char*) = IOServiceMatching;
