/* Recovered representation views, not imported SDK declarations.
 * No target code is executed. Compile-time assertions test the recovered
 * widths, packing, and offset arithmetic for the requested Clang target.
 */
#include <stddef.h>
#include <stdint.h>

struct fp_method26_descriptor {
    uint64_t user_address;
    uint32_t extent;
    uint32_t opaque0c;
};

#pragma pack(push, 4)
struct fp_user_header {
    uint32_t bits, size, remote_name, local_name, voucher_name;
    int32_t id;
};
struct fp_kernel_header {
    uint32_t bits, size;
    uint64_t remote_port_object, local_port_object;
    uint32_t voucher;
    int32_t id;
};
struct fp_ool_descriptor {
    uint64_t address;
    uint8_t deallocate, copy, padding, type;
    uint32_t extent;
};
struct fp_rpc_request_body {
    uint32_t descriptor_count;
    struct fp_ool_descriptor input;
    uint8_t ndr[8];
    uint32_t repeated_extent;
    uint64_t scalar0, scalar1, scalar2;
};
struct fp_rpc_reply_body {
    uint32_t descriptor_count;
    struct fp_ool_descriptor output0, output1;
    uint8_t ndr[8];
    uint8_t fixed_record0[136], fixed_record1[172];
    uint32_t repeated_extent0, repeated_extent1;
};
struct fp_user_request {
    struct fp_user_header header;
    struct fp_rpc_request_body body;
};
struct fp_kernel_request {
    struct fp_kernel_header header;
    struct fp_rpc_request_body body;
};
struct fp_user_reply {
    struct fp_user_header header;
    struct fp_rpc_reply_body body;
};
struct fp_kernel_reply {
    struct fp_kernel_header header;
    struct fp_rpc_reply_body body;
};
struct fp_audit_trailer_view {
    uint32_t type, size, seqno;
    uint32_t security_token[2];
    uint32_t audit_token[8];
};
#pragma pack(pop)

#define SIZE(type, expected) \
    _Static_assert(sizeof(struct type) == (expected), #type " size")
#define AT(type, field, expected) \
    _Static_assert(offsetof(struct type, field) == (expected), #type "." #field)
SIZE(fp_method26_descriptor, 16);
AT(fp_method26_descriptor, extent, 8);
AT(fp_method26_descriptor, opaque0c, 12);
SIZE(fp_user_header, 24);
SIZE(fp_kernel_header, 32);
SIZE(fp_ool_descriptor, 16);
AT(fp_ool_descriptor, type, 11);
AT(fp_ool_descriptor, extent, 12);
SIZE(fp_rpc_request_body, 56);
SIZE(fp_rpc_reply_body, 360);
SIZE(fp_user_request, 80);
SIZE(fp_kernel_request, 88);
SIZE(fp_user_reply, 384);
SIZE(fp_kernel_reply, 392);
AT(fp_user_request, body.input, 0x1c);
AT(fp_kernel_request, body.input, 0x24);
AT(fp_user_request, body.input.extent, 0x28);
AT(fp_kernel_request, body.input.extent, 0x30);
AT(fp_user_request, body.ndr, 0x2c);
AT(fp_kernel_request, body.ndr, 0x34);
AT(fp_user_request, body.repeated_extent, 0x34);
AT(fp_kernel_request, body.repeated_extent, 0x3c);
AT(fp_user_request, body.scalar0, 0x38);
AT(fp_kernel_request, body.scalar0, 0x40);
AT(fp_user_reply, body.output0, 0x1c);
AT(fp_kernel_reply, body.output0, 0x24);
AT(fp_user_reply, body.output1, 0x2c);
AT(fp_kernel_reply, body.output1, 0x34);
AT(fp_user_reply, body.ndr, 0x3c);
AT(fp_kernel_reply, body.ndr, 0x44);
AT(fp_user_reply, body.fixed_record0, 0x44);
AT(fp_kernel_reply, body.fixed_record0, 0x4c);
AT(fp_user_reply, body.fixed_record1, 0xcc);
AT(fp_kernel_reply, body.fixed_record1, 0xd4);
AT(fp_user_reply, body.repeated_extent0, 0x178);
AT(fp_kernel_reply, body.repeated_extent0, 0x180);
AT(fp_user_reply, body.repeated_extent1, 0x17c);
AT(fp_kernel_reply, body.repeated_extent1, 0x184);
SIZE(fp_audit_trailer_view, 52);
AT(fp_audit_trailer_view, audit_token, 20);
