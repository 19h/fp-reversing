#include <CoreFoundation/CFMachPort.h>
#include <CoreFoundation/CFRunLoop.h>
#include <mach/message.h>
#include <stddef.h>
_Static_assert(sizeof(CFMachPortContext)==40,"daemon zero context");
_Static_assert(offsetof(CFMachPortContext,info)==8,"context info");
_Static_assert(sizeof(CFRunLoopSourceContext1)==72,"source1 context");
_Static_assert(offsetof(CFRunLoopSourceContext1,getPort)==56,"get-port callback");
_Static_assert(offsetof(CFRunLoopSourceContext1,perform)==64,"perform callback");
_Static_assert(sizeof(mach_msg_header_t)==24,"user header");
_Static_assert(sizeof(mach_msg_max_trailer_t)==68,"requested maximum trailer");
_Static_assert(MACH_RCV_TRAILER_AV==7,"AV selector");
_Static_assert((MACH_RCV_MSG|MACH_RCV_LARGE|MACH_RCV_VOUCHER|MACH_RCV_TRAILER_ELEMENTS(7))==0x07000806,"native receive options");
static void callback(CFMachPortRef port, void *message, CFIndex size, void *info) {}
static CFMachPortCallBack signature=callback;
