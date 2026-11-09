#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#include <mach/mig_errors.h>
struct kernel_header32 {
    uint32_t bits, size;
    uint64_t remote_object, local_object;
    uint32_t voucher, id;
};
struct body24 { NDR_record_t ndr; uint64_t address, size; };
struct kernel_request56 { struct kernel_header32 header; struct body24 body; };
/* Inline field extent; header bytes avoid implying a naturally padded C
 * reply structure's sizeof is the original 44-byte message extent. */
struct kernel_reply_extent44 { unsigned char header[32]; NDR_record_t ndr; int32_t result; };
struct routine32 { uint64_t impl, stub; uint32_t arity, word14, descriptors, reply_size; };
struct hash24 { uint32_t id, policy; uint64_t stub; uint32_t reply_size, descriptors; };
_Static_assert(sizeof(struct kernel_header32)==32,"kernel header");
_Static_assert(offsetof(struct kernel_header32,id)==28,"kernel id");
_Static_assert(sizeof(struct kernel_request56)==56,"kernel request");
_Static_assert(sizeof(struct kernel_reply_extent44)==44,"kernel inline reply extent");
_Static_assert(sizeof(struct routine32)==32,"routine stride");
_Static_assert(sizeof(struct hash24)==24,"hash stride");
_Static_assert(sizeof(mach_msg_header_t)==24,"user header");
_Static_assert(MIG_BAD_ARGUMENTS==-304,"bad-arguments code");
uint32_t reply_id(uint32_t id) { return id+100; }
