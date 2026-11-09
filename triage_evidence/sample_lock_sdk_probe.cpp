#include <IOKit/IOLocks.h>

static_assert(sizeof(IOLock *) == 8);
static_assert(sizeof(IORWLock *) == 8);
static_assert(__is_same(decltype(&IOLockLock), void (*)(IOLock *)));
static_assert(__is_same(decltype(&IOLockUnlock), void (*)(IOLock *)));
static_assert(__is_same(decltype(&IORWLockWrite), void (*)(IORWLock *)));
static_assert(__is_same(decltype(&IORWLockUnlock), void (*)(IORWLock *)));

extern "C" unsigned long sample_lock_pointer_widths() {
    return sizeof(IOLock *) | (sizeof(IORWLock *) << 8);
}
