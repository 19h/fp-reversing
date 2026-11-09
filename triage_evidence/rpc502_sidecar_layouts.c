#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Installed SDK contract only: native library version remains unattested. */
_Static_assert(sizeof(int)==4,"open/fstat result and descriptor width");
_Static_assert(O_RDONLY==0,"observed open flags");
_Static_assert(sizeof(struct stat)==144,"LP64 Darwin stat extent");
_Static_assert(offsetof(struct stat,st_mode)==4,"mode offset");
_Static_assert(offsetof(struct stat,st_size)==96,"file size offset");
_Static_assert(sizeof(((struct stat *)0)->st_size)==8,"file size width in bytes");
