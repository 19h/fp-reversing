#include <IOKit/IOLocks.h>

static_assert(sizeof(IORWLock *) == 8);
static_assert(__is_same(decltype(&IORWLockAlloc), IORWLock *(*)(void)));
static_assert(__is_same(decltype(&IORWLockFree), void (*)(IORWLock *)));

extern "C" unsigned long rw_lifecycle_pointer_width() {
    return sizeof(IORWLock *);
}
