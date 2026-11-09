#include <stddef.h>
#include <stdint.h>
#include <mach/message.h>
#include <xpc/xpc.h>
#include <Security/SecCode.h>

/* Partial, observed private layouts; no private symbol names are invented. */
struct arcade_peer_block {
    void *isa;
    uint32_t flags, reserved;
    void (*invoke)(void *, xpc_object_t);
    void *descriptor;
    xpc_connection_t captured_peer;
};
_Static_assert(sizeof(void *) == 8, "64-bit ABI");
_Static_assert(sizeof(audit_token_t) == 32, "audit token");
_Static_assert(sizeof(struct arcade_peer_block) == 40, "block plus peer capture");
_Static_assert(offsetof(struct arcade_peer_block, invoke) == 16, "block invoke");
_Static_assert(offsetof(struct arcade_peer_block, descriptor) == 24, "block descriptor");
_Static_assert(offsetof(struct arcade_peer_block, captured_peer) == 32, "peer capture");
_Static_assert(sizeof(int) == 4 && sizeof(int64_t) == 8, "status widths");
_Static_assert(__builtin_types_compatible_p(__typeof__(&xpc_int64_get_value),
    int64_t (*)(xpc_object_t)), "XPC status input is signed64");
_Static_assert(__builtin_types_compatible_p(__typeof__(&xpc_connection_set_peer_code_signing_requirement),
    int (*)(xpc_connection_t, const char *)), "XPC requirement API returns int");

