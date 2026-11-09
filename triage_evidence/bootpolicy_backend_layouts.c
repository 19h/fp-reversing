#include <stddef.h>
#include <stdint.h>

/* Caller-observed wire layouts, not complete firmware or public API types. */
struct bp_sep_header {
    uint32_t magic;
    uint32_t command_or_status;
    uint8_t remaining_header[24];
};
struct bp_security_request {
    struct bp_sep_header header;
    uint16_t policy_bytes;
    uint8_t reserved_body[6];
    uint8_t policy[0x4000];
};
struct bp_security_reply {
    struct bp_sep_header header;
    uint32_t mode;
};
struct observed_dispatch2022 {
    uint64_t function;
    uint32_t scalar_in;
    uint32_t structure_in;
    uint32_t scalar_out;
    uint32_t structure_out;
    uint8_t allow_async;
    uint8_t padding[7];
    uint64_t check_entitlement;
};
struct __attribute__((packed)) bp_ioconnect_request {
    uint32_t header[6];
    uint8_t ndr[8];
    uint32_t selector;
    uint32_t scalar_count;
    uint32_t inband_bytes;
    uint64_t input_address;
    uint64_t input_bytes;
    uint32_t output_inband_capacity;
    uint32_t scalar_output_capacity;
    uint64_t output_address;
    uint64_t output_capacity;
};
struct __attribute__((packed)) bp_ioopen_reply {
    uint32_t header[6];
    uint32_t descriptor_count;
    uint8_t connection_descriptor[12];
    uint8_t ndr[8];
    uint32_t driver_status;
};
_Static_assert(sizeof(struct bp_sep_header)==0x20,"SEP header prefix");
_Static_assert(sizeof(struct bp_security_request)==0x4028,"command17 request");
_Static_assert(offsetof(struct bp_security_request,policy_bytes)==0x20,"policy extent");
_Static_assert(offsetof(struct bp_security_request,policy)==0x28,"policy start");
_Static_assert(sizeof(struct bp_security_reply)==0x24,"command17 fixed reply");
_Static_assert(offsetof(struct bp_security_reply,mode)==0x20,"mode output");
_Static_assert(sizeof(struct observed_dispatch2022)==40,"2022 dispatch record");
_Static_assert(offsetof(struct observed_dispatch2022,allow_async)==24,"async flag");
_Static_assert(offsetof(struct observed_dispatch2022,check_entitlement)==32,"entitlement field");
_Static_assert(sizeof(struct bp_ioconnect_request)==0x54,"empty scalar/inband request");
_Static_assert(offsetof(struct bp_ioconnect_request,input_address)==0x2c,"input VA");
_Static_assert(offsetof(struct bp_ioconnect_request,input_bytes)==0x34,"input extent");
_Static_assert(offsetof(struct bp_ioconnect_request,output_inband_capacity)==0x3c,"inline reply capacity");
_Static_assert(sizeof(struct bp_ioopen_reply)==0x34,"successful complex open reply");
_Static_assert(offsetof(struct bp_ioopen_reply,connection_descriptor)==0x1c,"returned port");
_Static_assert(offsetof(struct bp_ioopen_reply,driver_status)==0x30,"separate driver status");
