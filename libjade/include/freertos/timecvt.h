#ifndef _LIBJADE_FREERTOS_TIMECVT_H_
#define _LIBJADE_FREERTOS_TIMECVT_H_ 1

#include "task.h"
#include <time.h>

#define TIMECVT_STATIC_ASSERT(cond)                                                                                    \
    do {                                                                                                               \
        (void)sizeof(char[1 - 2 * !(cond)]);                                                                           \
    } while (0)

static inline struct timespec timespec_from_ticktype(TickType_t ticks)
{
    // The code below is based on portTICK_PERIOD_MS == 1
    TIMECVT_STATIC_ASSERT(portTICK_PERIOD_MS == 1);
    struct timespec ts;
    ts.tv_sec = ticks / 1000;
    ts.tv_nsec = (ticks % 1000) * 1000000;
    return ts;
}

#undef TIMECVT_STATIC_ASSERT

static inline struct timespec absolute_timespec_from_ticktype(TickType_t ticks)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct timespec timeout = timespec_from_ticktype(ticks);
    timeout.tv_sec += now.tv_sec;
    timeout.tv_nsec += now.tv_nsec;
    if (timeout.tv_nsec >= 1000000000) {
        timeout.tv_sec += 1;
        timeout.tv_nsec -= 1000000000;
    }
    return timeout;
}

#endif // _LIBJADE_FREERTOS_TIMECVT_H_
