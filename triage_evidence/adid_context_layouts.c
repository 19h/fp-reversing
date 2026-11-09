/* Analyst ABI declarations; compile to assembly only. */
#include <CoreFoundation/CFData.h>
#include <CoreFoundation/CFPropertyList.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFNumber.h>
#include <stdint.h>
_Static_assert(sizeof(CFIndex) == 8, "signed CFIndex width");
_Static_assert(sizeof(CFOptionFlags) == 8, "CF option width");
_Static_assert(sizeof(CFPropertyListFormat) == 8, "format width");
_Static_assert(kCFNumberSInt32Type == 3, "numeric conversion selector");
_Static_assert(kCFPropertyListImmutable == 0, "immutable property-list options");
_Static_assert(kCFPropertyListXMLFormat_v1_0 == 100, "fixture XML format");
CFDataRef analyst_data(const uint8_t *p, CFIndex n) {
    return CFDataCreateWithBytesNoCopy(0, p, n, kCFAllocatorNull);
}
CFPropertyListRef analyst_parse(CFAllocatorRef allocator, CFDataRef data) {
    return CFPropertyListCreateWithData(allocator, data, kCFPropertyListImmutable, 0, 0);
}
Boolean analyst_uid(CFNumberRef number, int32_t *output) {
    return CFNumberGetValue(number, kCFNumberSInt32Type, output);
}
