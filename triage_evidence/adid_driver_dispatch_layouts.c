/* Analyst SDK declarations; compile only,never invoke these APIs. */
#include <unistd.h>
#include <gethostuuid.h>
#include <stddef.h>
_Static_assert(sizeof(uuid_t)==16,"host UUID output extent");
_Static_assert(sizeof(struct timespec)==16,"timeout extent");
_Static_assert(sizeof(((struct timespec *)0)->tv_sec)==8,"seconds width");
_Static_assert(sizeof(((struct timespec *)0)->tv_nsec)==8,"nanoseconds width");
_Static_assert(offsetof(struct timespec,tv_nsec)==8,"nanoseconds offset");
_Static_assert(sizeof(off_t)==8 && sizeof(int)==4,"ftruncate argument widths");
int analyst_host_uuid(uuid_t output,const struct timespec *timeout) {
    return gethostuuid(output,timeout);
}
int analyst_truncate(int fd,off_t length) { return ftruncate(fd,length); }
