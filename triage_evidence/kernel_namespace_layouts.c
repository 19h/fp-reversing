/* Partial original-image layouts. Opaque fields and pointer authentication
 * are not modeled by this compilation. No target program is linked or run. */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
struct entry_prefix { u64 object; u32 bits; u8 opaque[12]; };
struct space_prefix { u8 opaque0[0x48]; u64 encoded_table; u64 task; u64 policy; };
struct reply_port_prefix {
    u8 type; u8 opaque1[3]; u32 refs; u8 opaque8[8];
    u32 flags; u8 opaque14[0x2c]; u64 owner_thread;
    u8 opaque48[0x10]; u64 sync_inheritor; u32 diagnostic_pid;
};
#define OFF(T,F) __builtin_offsetof(struct T,F)
_Static_assert(sizeof(u64)==8 && sizeof(u32)==4,"integer widths");
_Static_assert(sizeof(struct entry_prefix)==24,"namespace entry stride");
_Static_assert(OFF(entry_prefix,bits)==8,"entry capability bits");
_Static_assert(OFF(space_prefix,encoded_table)==0x48,"table token");
_Static_assert(OFF(space_prefix,policy)==0x58,"authenticated policy field");
_Static_assert(OFF(reply_port_prefix,refs)==4,"object reference count");
_Static_assert(OFF(reply_port_prefix,flags)==0x10,"sync state flags");
_Static_assert(OFF(reply_port_prefix,owner_thread)==0x40,"owner thread");
_Static_assert(OFF(reply_port_prefix,sync_inheritor)==0x58,"authenticated state union");
_Static_assert(OFF(reply_port_prefix,diagnostic_pid)==0x60,"diagnostic PID");
