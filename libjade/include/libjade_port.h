/*
 * Portable utility functions and macros for libjade.
 */

#ifndef _LIBJADE_PORT_H_
#define _LIBJADE_PORT_H_ 1

#include "jade_log.h"

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#else
#include <endian.h>
#endif

#include <pthread.h>

// Portable replacement for pthread_setname_np() setting name for the current thread.
static inline void libjade_thread_setname(const char* name)
{
#if defined(__APPLE__)
    // MacOS does't support setting name for other threads
    const int ret = pthread_setname_np(name);
#else
    const int ret = pthread_setname_np(pthread_self(), name);
#endif
    if (ret) {
        JADE_LOGW("thread set name failed for task %s", name);
    }
}

// Assert the calling thread's FreeRTOS task-local storage is empty (see libjade/task.c)
void libjade_tls_init(void);

// Discard the calling thread's FreeRTOS task-local storage (see libjade/task.c),
// invoking any registered 'delete' callbacks as the RTOS does when a task is deleted
void libjade_tls_reset(void);

#ifdef __APPLE__

#include <stdlib.h>
#include <unistd.h>

static inline ssize_t libjade_getrandom(void* buf, size_t buflen)
{
    arc4random_buf(buf, buflen);
    return buflen;
}

#else // __APPLE__

#include <sys/random.h>

static inline ssize_t libjade_getrandom(void* buf, size_t buflen) { return getrandom(buf, buflen, 0); }

#endif // __APPLE__

#endif // _LIBJADE_PORT_H_
