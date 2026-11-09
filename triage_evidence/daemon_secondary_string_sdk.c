#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
_Static_assert(sizeof(long) == 8, "strtol result width");
_Static_assert(sizeof(char *) == 8, "end pointer width");
long decimal_parse(const char *s, char **end) { return strtol(s, end, 10); }
Boolean ascii_convert(CFStringRef s, char buffer[32])
{
    return CFStringGetCString(s, buffer, 32, kCFStringEncodingASCII);
}
