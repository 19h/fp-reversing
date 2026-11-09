#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/signal.h>
#include <CoreFoundation/CFFileDescriptor.h>
#include <CoreServices/CoreServices.h>
#include <xpc/xpc.h>

_Static_assert(sizeof(struct stat) == 144, "stat width");
_Static_assert(offsetof(struct stat, st_mode) == 4, "mode offset");
_Static_assert(offsetof(struct stat, st_uid) == 16, "uid offset");
_Static_assert(offsetof(struct stat, st_gid) == 20, "gid offset");
_Static_assert(offsetof(struct stat, st_size) == 96, "size offset");
_Static_assert(sizeof(struct kevent) == 32, "kevent width");
_Static_assert(sizeof(CFFileDescriptorContext) == 40, "CF FD context width");
_Static_assert(XPC_CONNECTION_MACH_SERVICE_LISTENER == 1, "listener flag");
_Static_assert((O_RDONLY | O_SHLOCK | O_NOFOLLOW) == 0x110, "source flags");
_Static_assert((O_WRONLY | O_EXLOCK | O_NOFOLLOW | O_CREAT) == 0x321, "destination flags");
_Static_assert(EVFILT_SIGNAL == -6 && (EV_ADD | EV_ENABLE) == 5 && SIGTERM == 15, "signal registration");

const uint64_t adid_startup_layout[] = {
    sizeof(struct statfs), offsetof(struct statfs, f_flags),
    offsetof(struct statfs, f_fstypename), offsetof(struct statfs, f_mntonname),
    offsetof(struct statfs, f_mntfromname),
    S_IFMT, S_IFDIR, S_IFREG,
    EVFILT_VNODE, EV_ADD, EV_CLEAR, NOTE_WRITE, NOTE_RENAME, NOTE_DELETE,
    kCFFileDescriptorReadCallBack,
    O_RDONLY, O_WRONLY, O_SHLOCK, O_EXLOCK, O_NOFOLLOW, O_CREAT,
    O_EVTONLY, O_CLOEXEC, EVFILT_SIGNAL, EV_ENABLE, SIGTERM
};

Boolean adid_backup_query_ABI(CFURLRef url) {
    return CSBackupIsItemExcluded(url, NULL);
}
OSStatus adid_backup_set_ABI(CFURLRef url) {
    return CSBackupSetItemExcluded(url, true, false);
}
int adid_open_source_ABI(const char *path) {
    return open(path, O_RDONLY | O_SHLOCK | O_NOFOLLOW);
}
int adid_open_destination_ABI(const char *path) {
    return open(path, O_WRONLY | O_EXLOCK | O_NOFOLLOW | O_CREAT, 0666);
}

unsigned char adid_vmm_byte(int status, unsigned value) {
    return (unsigned char)(9 + (status == 0 && value == 1));
}
