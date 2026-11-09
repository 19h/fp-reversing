/* Compile only;no target API is called or linked. */
#include <stdint.h>
#include <stddef.h>
#include <servers/bootstrap.h>
#include <mach/mig_errors.h>
struct lookup_record {
    uint32_t encoded_status, unknown4;
    uint32_t *port_name_output;
    uint32_t *flags_output;
    uint8_t encoded_flag, unknown25[3];
    uint32_t encoded_tag;
};
_Static_assert(sizeof(struct lookup_record)==32,"source lookup record extent");
_Static_assert(offsetof(struct lookup_record,port_name_output)==8,"port output pointer offset");
_Static_assert(offsetof(struct lookup_record,flags_output)==16,"flags output pointer offset");
_Static_assert(offsetof(struct lookup_record,encoded_flag)==24,"byte flag offset");
_Static_assert(offsetof(struct lookup_record,encoded_tag)==28,"word tag offset");
_Static_assert(BOOTSTRAP_UNKNOWN_SERVICE==1102,"fallback selector");
_Static_assert(MIG_BAD_ARGUMENTS==-304,"original daemon structural rejection");
_Static_assert(MIG_REPLY_MISMATCH==-301,"original client reply-ID rejection");
