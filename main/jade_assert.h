#ifndef JADE_ASSERT_H_
#define JADE_ASSERT_H_

#include "jade_log.h"
#include <stdbool.h>
#include <stdlib.h>

__attribute__((__noreturn__)) void jade_abort(const char* file, const int line_n);

void __wrap_abort(void);

#ifndef __FILE_NAME__
// Compiling natively: work around a lack of __FILE_NAME__ support
#define __FILE_NAME__ __FILE__
#endif

// Abort, after clearing sensitive memory areas
#define JADE_ABORT()                                                                                                   \
    do {                                                                                                               \
        jade_abort(__FILE_NAME__, __LINE__);                                                                           \
        __builtin_unreachable();                                                                                       \
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

// Compile-time assert that "cond" is true. If false compilation will fail.
#define JADE_STATIC_ASSERT(cond)                                                                                       \
    do {                                                                                                               \
        (void)sizeof(char[1 - 2 * !(cond)]);                                                                           \
    } while (0)

// Macro to make an call and assert that the result is 0
#define JADE_ZERO_VERIFY(expr)                                                                                         \
    do {                                                                                                               \
        const int _r = (expr);                                                                                         \
        JADE_ASSERT_MSG(!_r, "ERROR: %d", _r);                                                                         \
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

#endif // JADE_ASSERT_H_
