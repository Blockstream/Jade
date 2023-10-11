#ifndef JADE_ASSERT_H_
#define JADE_ASSERT_H_

#include "jade_log.h"
#include <stdlib.h>

void jade_abort(const char* file, const int line_n);

// Abort, after clearing sensitive memory areas
// Note the call to abort() is redundant as jade_abort() will never return but it
// means the compiler knows this is terminal
#define JADE_ABORT()                                                                                                   \
    do {                                                                                                               \
        jade_abort(__FILE__, __LINE__);                                                                                \
        abort();                                                                                                       \
    } while (false)

// Assert (ie. abort if false)
#define JADE_ASSERT(expr)                                                                                              \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            JADE_LOGE("Assertion failed: %s", #expr);                                                                  \
            JADE_ABORT();                                                                                              \
        }                                                                                                              \
    } while (false)

// Assert with explicit error message
#define JADE_ASSERT_MSG(expr, fmt, ...)                                                                                \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            JADE_LOGE("Assertion failed: %s", #expr);                                                                  \
            JADE_LOGE(fmt, ##__VA_ARGS__);                                                                             \
            JADE_ABORT();                                                                                              \
        }                                                                                                              \
    } while (false)

// Assert pointer-to-pointer is non-null, then set pointee to zero
#define JADE_INIT_OUT_PPTR(pptr)                                                                                       \
    do {                                                                                                               \
        JADE_ASSERT(pptr);                                                                                             \
        *pptr = NULL;                                                                                                  \
    } while (false)

// Assert pointer-to-numeric is non-null, then set pointee to zero
#define JADE_INIT_OUT_SIZE(psize)                                                                                      \
    do {                                                                                                               \
        JADE_ASSERT(psize);                                                                                            \
        *psize = 0;                                                                                                    \
    } while (false)

#endif

// Macro to try to take what should be an available/low-contention mutex
// Warns if taking longer than expected, eventually asserts
#define JADE_SEMAPHORE_TAKE(s)                                                                                         \
    do {                                                                                                               \
        int attempt = 0;                                                                                               \
        while (xSemaphoreTake(s, 500 / portTICK_PERIOD_MS) != pdTRUE) {                                                \
            JADE_LOGW("Failed to acquire mutex %p, attempt %u", (void*)s, ++attempt);                                  \
            JADE_ASSERT_MSG(attempt < 10, "Fatal failure to acquire mutex, exhausted retries");                        \
        }                                                                                                              \
        JADE_LOGD("Aquired mutex %p", (void*)s);                                                                       \
    } while (false)

#define JADE_SEMAPHORE_GIVE(s)                                                                                         \
    do {                                                                                                               \
        xSemaphoreGive(s);                                                                                             \
        JADE_LOGD("Released mutex %p", (void*)s);                                                                      \
    } while (false)
