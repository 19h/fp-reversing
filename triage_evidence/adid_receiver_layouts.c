#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#include <mach/message.h>
#include <mach-o/fixup-chains.h>
#include <bsm/libbsm.h>
#include <CoreFoundation/CFNumber.h>

/* Recovered private record roles; source semantic typedefs remain unknown. */
struct adid_core_record {
    uint32_t encoded_operation;
    uint32_t status;
    const void *input;
    void **output;
    uint64_t encoded_input_size;
    const audit_token_t *audit;
    size_t *output_size;
};
_Static_assert(sizeof(struct adid_core_record) == 48, "record extent");
_Static_assert(offsetof(struct adid_core_record, input) == 8, "input offset");
_Static_assert(offsetof(struct adid_core_record, output) == 16, "output offset");
_Static_assert(offsetof(struct adid_core_record, encoded_input_size) == 24, "size offset");
_Static_assert(offsetof(struct adid_core_record, audit) == 32, "audit offset");
_Static_assert(offsetof(struct adid_core_record, output_size) == 40, "out size offset");
_Static_assert(sizeof(audit_token_t) == 32, "audit token width");
_Static_assert(DYLD_CHAINED_PTR_ARM64E == 1, "format1 identity");
_Static_assert(sizeof(struct dyld_chained_ptr_arm64e_bind) == 8, "bind width");
_Static_assert(kCFNumberSInt32Type == 3, "observed CF number conversion");

uint8x16_t adid_xor3_model(uint8x16_t a, uint8x16_t b, uint8x16_t c) {
    return veorq_u8(veorq_u8(a, b), c);
}

void adid_audit_pid_ABI(audit_token_t token, pid_t *pid) {
    audit_token_to_au32(token, NULL, NULL, NULL, NULL, NULL, pid, NULL, NULL);
}
