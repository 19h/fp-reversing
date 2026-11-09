#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
_Static_assert(sizeof(CFTypeID) == 8, "CFTypeID width");
_Static_assert(sizeof(int32_t) == 4, "signed32 output width");
_Static_assert(kCFNumberSInt32Type == 3, "source conversion type");
Boolean read_signed32(CFNumberRef v, int32_t *out)
{
    return CFNumberGetValue(v, kCFNumberSInt32Type, out);
}
Boolean read_ascii32(CFStringRef v, char out[32])
{
    return CFStringGetCString(v, out, 32, kCFStringEncodingASCII);
}
