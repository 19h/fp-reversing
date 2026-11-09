#include <stddef.h>
#include <stdint.h>
#include <CoreFoundation/CFMachPort.h>
#include <CoreFoundation/CFRunLoop.h>
#include <servers/bootstrap.h>

/* Selected private fields, not a claim about an original C declaration. */
struct registration_record {
    CFMachPortRef *destination;
    const char *service_name;
    uint32_t encoded_status;
    uint32_t unknown_14;
    void *reserved_18;
    uint32_t encoded_control;
    uint32_t unknown_24;
};
struct service_header_prefix {
    void *record_array;
    uint64_t record_count;
    void *unknown_10;
    CFMachPortRef unfreed;
    CFMachPortRef fairplayd;
    CFMachPortRef fpsd;
    CFMachPortRef arcade_fpsd;
    void *unknown_38;
    CFMachPortRef fpsd_sim;
};
_Static_assert(sizeof(mach_port_t)==4,"namespace name width");
_Static_assert(sizeof(struct registration_record)==40,"private record extent");
_Static_assert(offsetof(struct registration_record,encoded_status)==16,"status field");
_Static_assert(offsetof(struct registration_record,encoded_control)==32,"control field");
_Static_assert(sizeof(struct service_header_prefix)==72,"selected header extent");
_Static_assert(offsetof(struct service_header_prefix,unfreed)==24,"first service slot");
_Static_assert(offsetof(struct service_header_prefix,fpsd_sim)==64,"last service slot");
_Static_assert(sizeof(CFMachPortContext)==40,"public callback context");
kern_return_t (*bootstrap_signature)(mach_port_t,const char *,mach_port_t *)=bootstrap_check_in;
void (*add_source_signature)(CFRunLoopRef,CFRunLoopSourceRef,CFRunLoopMode)=CFRunLoopAddSource;
