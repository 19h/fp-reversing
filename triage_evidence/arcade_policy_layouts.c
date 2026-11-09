#include <stdint.h>
#include <Security/SecCode.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
_Static_assert(sizeof(OSStatus)==4,"Security status is signed32");
_Static_assert((OSStatus)-1<0,"OSStatus signedness");
_Static_assert(kSecCSCheckAllArchitectures==1,"all architectures flag");
_Static_assert(kSecCSBasicValidateOnly==6,"basic excludes executable and resources");
_Static_assert((kSecCSCheckAllArchitectures|kSecCSBasicValidateOnly)==7,"basicCheck true flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&SecCodeCheckValidity),
    OSStatus(*)(SecCodeRef,SecCSFlags,SecRequirementRef)),"dynamic validity ABI");

