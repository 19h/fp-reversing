#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>

_Static_assert(sizeof(int) == 4, "int32 ABI");
_Static_assert(sizeof(void *) == 8, "pointer64 ABI");
_Static_assert(sizeof(size_t) == 8, "allocation size64 ABI");
_Static_assert(sizeof(off_t) == 8 && (off_t)-1 < 0, "signed off64 ABI");
_Static_assert(sizeof(struct stat) == 144, "stat extent");
_Static_assert(offsetof(struct stat, st_size) == 96, "file size offset");
_Static_assert(sizeof(((struct stat *)0)->st_size) == 8, "file size width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstat), int (*)(int, struct stat *)), "fstat signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&close), int (*)(int)), "close signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&malloc), void *(*)(size_t)), "malloc signature");

int metadata_probe(int descriptor, struct stat *metadata) {
    return fstat(descriptor, metadata);
}

void *size_probe(const struct stat *metadata) {
    return malloc((size_t)metadata->st_size);
}

int close_probe(int descriptor) {
    return close(descriptor);
}
