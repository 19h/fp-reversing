#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(kCFStringEncodingUTF8 == 0x08000100, "UTF8 encoding value");
_Static_assert(sizeof(CFIndex) == 8, "CFIndex bytes");
_Static_assert(sizeof(CFStringEncoding) == 4, "encoding bytes");
_Static_assert(sizeof(Boolean) == 1, "Boolean bytes");
CFIndex (*length_signature)(CFStringRef) = CFStringGetLength;
CFIndex (*maximum_signature)(CFIndex, CFStringEncoding) = CFStringGetMaximumSizeForEncoding;
Boolean (*convert_signature)(CFStringRef, char *, CFIndex, CFStringEncoding) = CFStringGetCString;
size_t (*strlen_signature)(const char *) = strlen;
void *(*malloc_signature)(size_t) = malloc;
void (*free_signature)(void *) = free;
