#include <stddef.h>
#include <stdint.h>
/* Reconstructed private records; compile-only layout checks. */
struct client_bits_record {
    const void *token;
    uint32_t encoded_status;
    uint32_t encoded_selector;
    uint32_t *state;
};
struct boolean_query_record {
    const char *name;
    uint8_t marker;
    uint8_t gap0[7];
    uint8_t *flag;
    uint32_t encoded_selector;
    uint8_t gap1[4];
    const void *token;
};
_Static_assert(sizeof(struct client_bits_record)==24, "bridge size");
_Static_assert(offsetof(struct client_bits_record,encoded_status)==8, "status");
_Static_assert(offsetof(struct client_bits_record,encoded_selector)==12, "control");
_Static_assert(offsetof(struct client_bits_record,state)==16, "state");
_Static_assert(sizeof(struct boolean_query_record)==40, "query size");
_Static_assert(offsetof(struct boolean_query_record,marker)==8, "marker");
_Static_assert(offsetof(struct boolean_query_record,flag)==16, "flag");
_Static_assert(offsetof(struct boolean_query_record,token)==32, "token");
uint32_t read_bridge_status(const struct client_bits_record *r)
{
    return r->encoded_status ^ UINT32_C(0x8b3dc651);
}
