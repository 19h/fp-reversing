#include <stdint.h>
#include <stddef.h>
/* Reconstructed storage extents; these are not original private typedefs. */
struct kernel_header { uint32_t bits, size; uint64_t remote, local; uint32_t voucher, id; };
struct canonical_header { struct kernel_header header; uint32_t descriptors; };
struct kernel_trailer { uint32_t type, advertised_size, sequence, security[2], audit[8], rest[4]; };
_Static_assert(sizeof(struct kernel_header)==32,"header");
_Static_assert(offsetof(struct kernel_header,remote)==8,"destination");
_Static_assert(offsetof(struct canonical_header,descriptors)==32,"descriptor count");
/* Only 36 canonical bytes are hashed; natural aggregate padding is excluded. */
_Static_assert(sizeof(struct kernel_trailer)==68,"copied trailer extent");
_Static_assert(offsetof(struct kernel_trailer,security)==12,"security token");
_Static_assert(offsetof(struct kernel_trailer,audit)==20,"audit token");
uint64_t queue_arguments(uint64_t destination) { return destination+0x28; }
