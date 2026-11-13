#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>

_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8, "integer/pointer ABI");
_Static_assert(sizeof(size_t) == 8, "size64 ABI");
_Static_assert(sizeof(ssize_t) == 8 && (ssize_t)-1 < 0, "signed read return64");
_Static_assert(sizeof(struct stat) == 144, "stat extent");
_Static_assert(offsetof(struct stat, st_size) == 96, "size offset");
_Static_assert(offsetof(struct stat, st_mtimespec) == 48, "modification-time offset");
_Static_assert(sizeof(struct timespec) == 16, "timestamp extent");
_Static_assert(offsetof(struct timespec, tv_sec) == 0, "seconds offset");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8, "nanoseconds offset");
_Static_assert(sizeof(((struct timespec *)0)->tv_sec) == 8, "seconds width");
_Static_assert(sizeof(((struct timespec *)0)->tv_nsec) == 8, "nanoseconds width");
_Static_assert((time_t)-1 < 0 && (long)-1 < 0, "signed timestamp fields");
_Static_assert(__builtin_types_compatible_p(__typeof__(&read), ssize_t (*)(int, void *, size_t)), "read signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&free), void (*)(void *)), "free signature");

ssize_t read_probe(int descriptor, void *buffer, const struct stat *metadata) {
    return read(descriptor, buffer, (size_t)metadata->st_size);
}

void timestamp_probe(struct timespec *output, const struct stat *metadata) {
    *output = metadata->st_mtimespec;
}
