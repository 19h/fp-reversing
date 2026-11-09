#include <stdint.h>
#include <stddef.h>
#include <Security/SecTrust.h>
/* Source-derived partial ivar view; labels below describe representation only. */
struct receipt80 {
    void *isa;
    void *slot08;
    void *slot10;
    void *slot18;
    void *slot20;
    void *slot28;
    void *slot30;
    void *slot38;
    uint8_t opaque16[16];
};
_Static_assert(sizeof(struct receipt80)==80,"original class_ro instance size");
_Static_assert(offsetof(struct receipt80,slot28)==0x28,"getAdamID storage");
_Static_assert(offsetof(struct receipt80,opaque16)==0x40,"opaque DSID buffer");
_Static_assert(kSecTrustResultProceed==1,"trust result1");
_Static_assert(kSecTrustResultUnspecified==4,"trust result4");
