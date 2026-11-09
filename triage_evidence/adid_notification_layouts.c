#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <notify.h>
#include <sys/time.h>

_Static_assert(sizeof(int) == 4, "libnotify token/check int32");
_Static_assert(sizeof(uint32_t) == 4, "libnotify status32");
_Static_assert(sizeof(time_t) == 8, "Darwin time_t64");
_Static_assert(sizeof(struct timeval) == 16, "Darwin timeval16");
_Static_assert(offsetof(struct timeval, tv_sec) == 0, "seconds offset0");
_Static_assert(offsetof(struct timeval, tv_usec) == 8, "microseconds offset8");
_Static_assert(sizeof(((struct timeval *)0)->tv_usec) == 4, "microseconds32");

uint32_t notification_abi(const char *name, int *token, int *changed)
{
    uint32_t status = notify_register_check(name, token);
    status |= notify_check(*token, changed);
    status |= notify_cancel(*token);
    status |= notify_post(name);
    return status;
}

int notification_clock(struct timeval *value, void (*cleanup)(void))
{
    int status = atexit(cleanup);
    return status | gettimeofday(value, NULL);
}
