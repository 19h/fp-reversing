#include <CoreFoundation/CoreFoundation.h>
_Static_assert(sizeof(CFTypeID) == 8, "CFTypeID width");
_Static_assert(sizeof(Boolean) == 1, "Boolean width");
Boolean entitlement_boolean(CFTypeRef value) {
    return CFGetTypeID(value) == CFBooleanGetTypeID()
        ? CFBooleanGetValue((CFBooleanRef)value) : 0;
}
