#include <stdint.h>
#include <stddef.h>
#include <Foundation/NSDistributedNotificationCenter.h>
struct repair_options_partial {
    uint8_t prefix[12];
    int32_t fairplay_status;
    uint8_t middle[32];
    uint64_t exit_reason;
};
_Static_assert(offsetof(struct repair_options_partial,fairplay_status)==12,"reference setter W2 field");
_Static_assert(offsetof(struct repair_options_partial,exit_reason)==48,"reference setter X2 field");
_Static_assert(NSDistributedNotificationPostToAllSessions==2,"notification option2");
_Static_assert((int32_t)UINT32_C(0xffff5a90)==-42352,"signed32 repair status");
