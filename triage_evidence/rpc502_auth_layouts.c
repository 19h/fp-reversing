#include <stddef.h>
#include <stdint.h>
struct observed_certificate_view {uint8_t unknown_prefix[0x490];uint8_t signature[256];uint32_t encoded_signature_size,digest_size;uint8_t encoded_digest[20];};
_Static_assert(offsetof(struct observed_certificate_view,signature)==0x490,"signature490");
_Static_assert(offsetof(struct observed_certificate_view,encoded_signature_size)==0x590,"size590");
_Static_assert(offsetof(struct observed_certificate_view,digest_size)==0x594,"digest_size594");
_Static_assert(offsetof(struct observed_certificate_view,encoded_digest)==0x598,"digest598");
_Static_assert(sizeof(struct observed_certificate_view)==0x5ac,"partial source view5ac");
uint32_t local_status(uint32_t raw,uint32_t prior){return (uint8_t)raw==0&&(uint8_t)prior==0x51?UINT32_C(0x8b3dc651):UINT32_C(0x74c29d8a);}
uint32_t signature_size(uint32_t stored){return stored^UINT32_C(0x8b3dc651);}
