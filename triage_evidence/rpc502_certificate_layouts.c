#include <stdint.h>
#include <stddef.h>
struct source_item_argument_view {uint32_t mode,pad4;uint64_t input;uint32_t status,pad20;uint64_t length_output,content_output;uint32_t available,pad44;uint64_t tag_output,consumed_output;};
struct source_parsed_item_view {uint32_t tag,length;uint64_t content;uint32_t total,pad20;uint64_t start;};
struct source_schema_row_view {uint32_t tag,pad4;uint64_t callback;uint32_t scalar,pad20;uint64_t opaque;uint32_t child,sibling,flags,pad44;};
struct source_digest100_view {uint8_t buffer[64];uint32_t counter0,counter1,state[5],output_size,algorithm;};
_Static_assert(sizeof(struct source_item_argument_view)==64,"accessed item argument64");
_Static_assert(offsetof(struct source_item_argument_view,available)==40,"available40");
_Static_assert(offsetof(struct source_item_argument_view,consumed_output)==56,"consumed56");
_Static_assert(sizeof(struct source_parsed_item_view)==32,"item32");
_Static_assert(offsetof(struct source_parsed_item_view,total)==16,"TLV span16");
_Static_assert(offsetof(struct source_parsed_item_view,start)==24,"start24");
_Static_assert(sizeof(struct source_schema_row_view)==48,"stride48");
_Static_assert(offsetof(struct source_schema_row_view,child)==32,"child32");
_Static_assert(offsetof(struct source_schema_row_view,flags)==40,"flags40");
_Static_assert(sizeof(struct source_digest100_view)==100,"observed digest view100");
_Static_assert(offsetof(struct source_digest100_view,state)==72,"states72");
_Static_assert(offsetof(struct source_digest100_view,algorithm)==96,"algorithm96");
uint32_t item_key(uintptr_t p) {return ((uint32_t)p^0xe732d262U)*0xba209ef7U;}
