/* Native-offset representations only; neither private C++ type is asserted. */
typedef __UINT64_TYPE__ u64;
typedef __UINT32_TYPE__ u32;
typedef __INT64_TYPE__ i64;
#define OFF(T,F) __builtin_offsetof(T,F)
struct constructor_arguments {
    u64 name_address;
    u32 result_token;
    u32 unknown_0c;
    i64 scalar0;
    i64 scalar1;
    u32 origin;
    u32 mode;
};
struct crypt_file_data_prefix {
    u64 name_address;
    u32 scalar0;
    u32 scalar1;
    u32 origin;
    u32 unknown_14;
};
struct text_session_prefix {
    u64 vptr;
    u64 unknown_08;
    u64 crypter;
    u64 token;
    u64 name_object;
    u32 scalar0;
    u32 scalar1;
    u32 origin;
    u32 unknown_34;
};
struct pager_callbacks_prefix { u64 page; u64 end; u64 session; };
_Static_assert(sizeof(struct constructor_arguments)==40,"constructor size");
_Static_assert(OFF(struct constructor_arguments,result_token)==8,"u32 result");
_Static_assert(OFF(struct constructor_arguments,scalar0)==16,"scalar0");
_Static_assert(OFF(struct constructor_arguments,origin)==32,"origin");
_Static_assert(OFF(struct constructor_arguments,mode)==36,"mode");
_Static_assert(sizeof(struct crypt_file_data_prefix)==24,"observed kernel hook record");
_Static_assert(OFF(struct crypt_file_data_prefix,origin)==16,"origin in hook record");
_Static_assert(sizeof(struct text_session_prefix)==56,"session allocation extent");
_Static_assert(OFF(struct text_session_prefix,token)==24,"session token");
_Static_assert(OFF(struct text_session_prefix,name_object)==32,"session name");
_Static_assert(OFF(struct text_session_prefix,origin)==48,"session origin");
_Static_assert(sizeof(struct pager_callbacks_prefix)==24,"callback prefix");
