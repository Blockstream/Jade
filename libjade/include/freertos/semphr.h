#ifndef _LIBJADE_FREERTOS_SEMPHR_H_
#define _LIBJADE_FREERTOS_SEMPHR_H_ 1

#include <freertos/projdefs.h>
#include <pthread.h>
#include <time.h>

typedef struct Semaphore {
    pthread_mutex_t mutex;
} * SemaphoreHandle_t;

static inline SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    SemaphoreHandle_t out = malloc(sizeof(struct Semaphore));
    if (!out) {
        abort();
    }
    int ret = pthread_mutex_init(&out->mutex, NULL);
    if (ret) {
        abort();
    }
    return out;
}

static inline SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    // FIXME: Create an actual signal-able semaphore, this is just
    // a stub.
    return xSemaphoreCreateMutex();
}

static inline void vSemaphoreDelete(SemaphoreHandle_t s)
{
    int ret = pthread_mutex_destroy(&s->mutex);
    if (ret) {
        abort();
    }
    free(s);
}

int xSemaphoreTake(SemaphoreHandle_t s, int timeout)
{
    // FIXME: timeout
    return pthread_mutex_lock(&s->mutex) ? pdFALSE : pdTRUE;
}

void xSemaphoreGive(SemaphoreHandle_t s)
{
    int ret = pthread_mutex_unlock(&s->mutex);
    if (ret) {
        abort();
    }
}

#endif // _LIBJADE_FREERTOS_SEMPHR_H_
