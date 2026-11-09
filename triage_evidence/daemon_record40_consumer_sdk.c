#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecTask.h>
_Static_assert(sizeof(audit_token_t) == 32, "audit token width");
_Static_assert(sizeof(CFAllocatorRef) == 8, "allocator reference width");
_Static_assert(kCFStringEncodingASCII == 0x0600, "encoding selector");
CFStringRef record40_string(CFAllocatorRef a, const char *s, CFAllocatorRef d) {
  return CFStringCreateWithCStringNoCopy(a, s, kCFStringEncodingASCII, d);
}
SecTaskRef record40_task(CFAllocatorRef a, const audit_token_t *t) {
  return SecTaskCreateWithAuditToken(a, *t);
}
CFTypeRef record40_query(SecTaskRef t, CFStringRef k, CFErrorRef *e) {
  return SecTaskCopyValueForEntitlement(t, k, e);
}
