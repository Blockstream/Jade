#ifndef _LIBJADE_FREERTOS_RINGBUF_H_
#define _LIBJADE_FREERTOS_RINGBUF_H_ 1

#include <freertos/projdefs.h>
#include <pthread.h>
#include <time.h>
#include <wally_map.h>

typedef struct Ringbuffer {
    struct wally_map m;
    pthread_mutex_t mutex; // We should use a semaphore to wake at some point
}* RingbufHandle_t;

typedef struct Ringbuffer StaticRingbuffer_t;

#define RINGBUF_TYPE_NOSPLIT 0

static inline RingbufHandle_t xRingbufferCreateStatic(
    size_t buff_len, int buff_type, uint8_t* storage, StaticRingbuffer_t* out)
{
    free(storage); // Jade uses an allocated buffer, which we don't need
    int ret = wally_map_init(1000, NULL, &out->m);
    if (ret != WALLY_OK) {
        abort();
    }
    ret = pthread_mutex_init(&out->mutex, NULL);
    if (ret) {
        abort();
    }
    return out;
}

static inline RingbufHandle_t xRingbufferCreate(size_t buff_len, int buff_type)
{
    RingbufHandle_t out = malloc(sizeof(struct Ringbuffer));
    if (!out) {
        abort();
    }
    int ret = wally_map_init(buff_len, NULL, &out->m);
    if (ret != WALLY_OK) {
        abort();
    }
    ret = pthread_mutex_init(&out->mutex, NULL);
    if (ret) {
        abort();
    }
    return out;
}

static inline void vRingbufferDelete(RingbufHandle_t rb)
{
    struct wally_map* m = &rb->m;
    int ret = pthread_mutex_destroy(&rb->mutex);
    if (ret) {
        abort();
    }
    ret = wally_map_clear(m);
    if (ret) {
        abort();
    }
}

static inline size_t xRingbufferGetMaxItemSize(RingbufHandle_t rb)
{
    return 0xffffffff; // ~4GB
}

static inline int xRingbufferSend(RingbufHandle_t rb, const void* item, size_t item_len, int wait_ticks)
{
    struct wally_map* m = &rb->m;

    int ret = pthread_mutex_lock(&rb->mutex);
    if (ret) {
        abort();
    }
    // Note an integer key in a wally map is denoted by:
    // { key = NULL, key_len = integer key value }
    // We increment the key for each message sent.
    const uint32_t cur_idx = m->num_items ? m->items[m->num_items - 1].key_len : 0;
    ret = wally_map_add_integer(m, cur_idx + 1, item, item_len);
    if (ret != WALLY_OK) {
        abort();
    }
    ret = pthread_mutex_unlock(&rb->mutex);
    if (ret) {
        abort();
    }
    return pdTRUE;
}

static inline void* xRingbufferReceive(RingbufHandle_t rb, size_t* item_len_out, int wait_ticks)
{
    struct wally_map* m = &rb->m;
    void* value = NULL;

    if (!wait_ticks) {
        wait_ticks = 1;
    }
    while (!value && wait_ticks--) {
        int ret = pthread_mutex_lock(&rb->mutex);
        if (ret) {
            abort();
        }
        if (m->num_items) {
            // Steal the first item from the wally_map to avoid copying
            *item_len_out = m->items[0].value_len;
            value = m->items[0].value;
            m->items[0].value = NULL;
            m->items[0].value_len = 0;
            ret = wally_map_remove_integer(m, m->items[0].key_len);
            if (ret != WALLY_OK) {
                abort();
            }
        }
        ret = pthread_mutex_unlock(&rb->mutex);
        if (ret) {
            abort();
        }
        if (!value && wait_ticks) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
            nanosleep(&ts, &ts);
            // FIXME: Loop sleeping if sleep interrupted
        }
    }
    return value;
}

static inline void vRingbufferReturnItem(RingbufHandle_t rb, void* item) { wally_free(item); }
#endif // _LIBJADE_FREERTOS_RINGBUF_H_
