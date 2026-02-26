#ifndef _LIBJADE_FREERTOS_SEMPHR_H_
#define _LIBJADE_FREERTOS_SEMPHR_H_ 1

#include <errno.h>
#include <freertos/projdefs.h>
#include <freertos/timecvt.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>

typedef enum {
    SEMAPHORE_TYPE_BINARY,
    SEMAPHORE_TYPE_MUTEX,
} SemaphoreType_t;

typedef struct Semaphore {
    SemaphoreType_t type;
    union {
        sem_t binary;
        pthread_mutex_t mutex;
    };
}* SemaphoreHandle_t;

static inline SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    SemaphoreHandle_t out = malloc(sizeof(struct Semaphore));
    if (out) {
        out->type = SEMAPHORE_TYPE_MUTEX;
        const int ret = pthread_mutex_init(&out->mutex, NULL);
        if (ret) {
            free(out);
            out = NULL;
        }
    }
    return out;
}

static inline SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    SemaphoreHandle_t out = malloc(sizeof(struct Semaphore));
    if (out) {
        out->type = SEMAPHORE_TYPE_BINARY;
        const int ret = sem_init(&out->binary, 0, 0);
        if (ret) {
            free(out);
            out = NULL;
        }
    }
    return out;
}

static inline void vSemaphoreDelete(SemaphoreHandle_t s)
{
    switch (s->type) {
    case SEMAPHORE_TYPE_BINARY:
        if (sem_destroy(&s->binary)) {
            abort();
        }
        break;
    case SEMAPHORE_TYPE_MUTEX:
        if (pthread_mutex_destroy(&s->mutex)) {
            abort();
        }
        break;
    }
    free(s);
}

static inline int xSemaphoreTake(SemaphoreHandle_t s, int timeout)
{
    struct timespec ts;
    int ret;
    switch (s->type) {
    case SEMAPHORE_TYPE_BINARY:
        if (timeout == portMAX_DELAY) {
            if (sem_wait(&s->binary)) {
                JADE_LOGE("Unknown error waiting for semaphore (sem_wait): %d", errno);
                abort();
            }
            return pdTRUE;
        }
        ts = absolute_timespec_from_ticktype(timeout);
        if (sem_timedwait(&s->binary, &ts)) {
            switch (errno) {
            case 0:
                break;
            case ETIMEDOUT:
                return pdFALSE;
            default:
                JADE_LOGE("Unknown error aquiring mutex (sem_timedwait): %d", errno);
                abort();
            }
        }
        break;
    case SEMAPHORE_TYPE_MUTEX:
        if (timeout == portMAX_DELAY) {
            ret = pthread_mutex_lock(&s->mutex);
            if (ret) {
                JADE_LOGE("Unknown error aquiring mutex (pthread_mutex_lock): %d", ret);
                abort();
            }
            return pdTRUE;
        }
        ts = absolute_timespec_from_ticktype(timeout);
        ret = pthread_mutex_timedlock(&s->mutex, &ts);
        switch (ret) {
        case 0:
            break;
        case ETIMEDOUT:
            return pdFALSE;
        default:
            JADE_LOGE("Unknown error aquiring mutex (pthread_mutex_timedlock): %d", ret);
            abort();
        }
        break;
    }
    return pdTRUE;
}

static inline void xSemaphoreGive(SemaphoreHandle_t s)
{
    switch (s->type) {
    case SEMAPHORE_TYPE_BINARY:
        if (sem_post(&s->binary)) {
            abort();
        }
        break;
    case SEMAPHORE_TYPE_MUTEX:
        if (pthread_mutex_unlock(&s->mutex)) {
            abort();
        }
        break;
    }
}

#endif // _LIBJADE_FREERTOS_SEMPHR_H_
