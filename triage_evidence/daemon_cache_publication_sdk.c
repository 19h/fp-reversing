#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
_Static_assert(sizeof(CFTypeRef) == 8, "arm64 CFTypeRef width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&CFRelease), void (*)(CFTypeRef)), "CFRelease returns void");
_Static_assert(__builtin_types_compatible_p(__typeof__(&free), void (*)(void *)), "free returns void");
void release_then_free(CFTypeRef object, void *allocation) {
    CFRelease(object);
    free(allocation);
}
