/* Analyst declarations only; compile to assembly, never link or execute. */
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <unistd.h>

_Static_assert(sizeof(struct stat) == 144, "Darwin arm64 stat extent");
_Static_assert(offsetof(struct stat, st_dev) == 0, "device offset");
_Static_assert(offsetof(struct stat, st_mode) == 4, "mode offset");
_Static_assert(offsetof(struct stat, st_nlink) == 6, "link count offset");
_Static_assert(offsetof(struct stat, st_ino) == 8, "inode offset");
_Static_assert(sizeof(((struct stat *)0)->st_ino) == 8, "inode width");
_Static_assert(sizeof(((struct stat *)0)->st_dev) == 4, "device width");
_Static_assert(sizeof(((struct stat *)0)->st_nlink) == 2, "link count width");
_Static_assert(offsetof(struct stat, st_size) == 96, "file extent offset");
_Static_assert(F_GETPATH == 50 && MAXPATHLEN == 1024, "path lookup ABI");
_Static_assert((O_WRONLY | O_CREAT | O_CLOEXEC) == 0x01000201, "lock open flags");
_Static_assert(sizeof(struct statfs) == 2168, "Darwin statfs extent");
_Static_assert(offsetof(struct statfs, f_flags) == 64, "mount flags offset");
_Static_assert(offsetof(struct statfs, f_fstypename) == 72, "filesystem type offset");
_Static_assert(sizeof(((struct statfs *)0)->f_fstypename) == 16, "filesystem type bound");
_Static_assert(MNT_LOCAL == 0x1000, "local mount flag");
_Static_assert(F_LOCK == 1 && F_ULOCK == 0, "lockf commands");

int analyst_getpath(int fd, char output[MAXPATHLEN]) {
    return fcntl(fd, F_GETPATH, output);
}

int analyst_lock_open(const char *path) {
    return open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
}

int analyst_mode(int fd) { return fchmod(fd, 0666); }
int analyst_lock(int fd) { return lockf(fd, F_LOCK, 0); }
