#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
_Static_assert(kCFNumberSInt64Type == 4, "CFNumber type4");
_Static_assert(sizeof(int64_t) == 8, "signed64 output bytes");
_Static_assert(sizeof(CFNumberType) == 8, "CFIndex based type");
_Static_assert(sizeof(Boolean) == 1, "Boolean result width");
Boolean (*number_signature)(CFNumberRef, CFNumberType, void *) = CFNumberGetValue;
CFStringRef (*format_signature)(CFAllocatorRef, CFDictionaryRef, CFStringRef, ...) = CFStringCreateWithFormat;
CFStringRef chip_format_abi(int64_t chip) {
    return CFStringCreateWithFormat(0, 0, CFSTR("%qi"), chip);
}
CFStringRef identity_format_abi(CFStringRef serial, CFStringRef empty,
                              CFStringRef chip, CFStringRef wifi,
                              CFStringRef bluetooth) {
    return CFStringCreateWithFormat(0, 0, CFSTR("%@%@%@%@%@"),
                                    serial, empty, chip, wifi, bluetooth);
}
