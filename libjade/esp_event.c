#include "esp_event.h"
#include "jade_assert.h"
#include "jade_log.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>

#ifdef CONFIG_LIBJADE_GUI

typedef struct {
    esp_event_base_t event_base;
    int32_t event_id;
    void* event_data;
    size_t event_data_size;
} event_t;

typedef struct {
    esp_event_base_t event_base;
    int32_t event_id;
    esp_event_handler_t handler;
    void* event_handler_arg;
    esp_event_handler_instance_t instance;
} event_handler_entry_t;

struct queue_item_t {
    struct queue_item_t* next;
    struct queue_item_t* prev;
    event_t payload;
};

static struct queue_item_t* _queue_head = NULL;
static struct queue_item_t* _queue_tail = NULL;
static pthread_mutex_t _queue_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct wally_map _event_handlers;
static pthread_mutex_t _event_handlers_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t _default_event_loop_task;
static uint32_t next_entry_id = 0;

void* _default_event_loop(void* params)
{
    while (true) {
        // get next event from queue
        if (pthread_mutex_lock(&_queue_mutex)) {
            JADE_ABORT();
        }
        struct queue_item_t* item = _queue_head;
        if (item) {
            // remove from queue
            _queue_head = item->next;
            if (_queue_head) {
                _queue_head->prev = NULL;
            } else {
                _queue_tail = NULL;
            }
        }
        if (pthread_mutex_unlock(&_queue_mutex)) {
            JADE_ABORT();
        }
        if (!item) {
            // no event, sleep a bit
            struct timespec ts = { 0, 1000000 }; // 1ms
            nanosleep(&ts, NULL);
            continue;
        }
        // dispatch event to handlers
        if (pthread_mutex_lock(&_event_handlers_mutex)) {
            JADE_ABORT();
        }
        for (size_t i = _event_handlers.num_items; i > 0; --i) {
            event_handler_entry_t entry;
            memcpy(&entry, _event_handlers.items[i - 1].value, sizeof(entry));
            if ((entry.event_base == ESP_EVENT_ANY_BASE || entry.event_base == item->payload.event_base)
                && (entry.event_id == ESP_EVENT_ANY_ID || entry.event_id == item->payload.event_id)) {
                // call handler
                entry.handler(entry.event_handler_arg, item->payload.event_base, item->payload.event_id,
                    item->payload.event_data);
            }
        }
        if (pthread_mutex_unlock(&_event_handlers_mutex)) {
            JADE_ABORT();
        }
        // free item
        free(item);
    }
    return NULL;
}

esp_err_t esp_event_loop_create_default(void)
{
    if (_default_event_loop_task) {
        JADE_LOGE("Default event loop already created");
        return ESP_ERR_INVALID_STATE;
    }
    // init event handlers map
    int ret = wally_map_init(1000, NULL, &_event_handlers);
    if (ret != WALLY_OK) {
        JADE_LOGE("Failed to initialize event handlers map");
        return ESP_FAIL;
    }
    // init queue
    JADE_ASSERT(!_queue_head);
    JADE_ASSERT(!_queue_tail);
    // init thread
    esp_err_t result = ESP_FAIL;
    if (pthread_create(&_default_event_loop_task, NULL, _default_event_loop, NULL)) {
        goto cleanup;
    }
    // all succeeded
    result = ESP_OK;
cleanup:
    if (result != ESP_OK) {
        if (_default_event_loop_task) {
            pthread_kill(_default_event_loop_task, SIGTERM);
            _default_event_loop_task = 0;
        }
    }
    return result;
}

esp_err_t esp_event_post(
    esp_event_base_t event_base, int32_t event_id, void* event_data, size_t event_data_size, TickType_t ticks_to_wait)
{
    // make event_t
    event_t event = {
        .event_base = event_base,
        .event_id = event_id,
        .event_data = event_data,
        .event_data_size = event_data_size,
    };
    // make queue item
    struct queue_item_t* item = malloc(sizeof(struct queue_item_t));
    if (!item) {
        return ESP_ERR_NO_MEM;
    }
    item->next = NULL;
    item->prev = NULL;
    item->payload = event;
    // add to queue
    if (pthread_mutex_lock(&_queue_mutex)) {
        JADE_ABORT();
    }
    if (!_queue_tail) {
        _queue_head = item;
        _queue_tail = item;
    } else {
        _queue_tail->next = item;
        item->prev = _queue_tail;
        _queue_tail = item;
    }
    if (pthread_mutex_unlock(&_queue_mutex)) {
        JADE_ABORT();
    }
    return ESP_OK;
}

esp_err_t esp_event_handler_instance_register(esp_event_base_t event_base, int32_t event_id,
    esp_event_handler_t event_handler, void* event_handler_arg, esp_event_handler_instance_t* instance)
{
    // get event handler mutex
    if (pthread_mutex_lock(&_event_handlers_mutex)) {
        return ESP_FAIL;
    }
    // create entry
    event_handler_entry_t entry = {
        .event_base = event_base,
        .event_id = event_id,
        .handler = event_handler,
        .event_handler_arg = event_handler_arg,
        .instance = NULL,
    };
    const uint32_t entry_id = ++next_entry_id;
    JADE_LOGD("Registering event handler instance id %u (%s, %d)", entry_id, event_base, event_id);
    entry.instance = (void*)(uintptr_t)entry_id;
    *instance = entry.instance;
    // add to map
    int ret = wally_map_add_integer(&_event_handlers, entry_id, (unsigned char*)&entry, sizeof(entry));
    JADE_ASSERT(ret == WALLY_OK);
    // release event handler mutex
    if (pthread_mutex_unlock(&_event_handlers_mutex)) {
        JADE_ABORT();
    }
    return ESP_OK;
}

esp_err_t esp_event_handler_instance_unregister(
    esp_event_base_t event_base, int32_t event_id, esp_event_handler_instance_t instance)
{
    // get event handler mutex
    if (pthread_mutex_lock(&_event_handlers_mutex)) {
        return ESP_FAIL;
    }
    // find entry
    uint32_t entry_id = (uint32_t)(uintptr_t)instance;
    JADE_LOGD("Unregistering event handler instance id %u (%s, %d)", entry_id, event_base, event_id);
    const struct wally_map_item* item = wally_map_get_integer(&_event_handlers, entry_id);
    JADE_ASSERT(item);
    event_handler_entry_t entry;
    memcpy(&entry, item->value, sizeof(entry));
    JADE_ASSERT(entry.event_base == event_base);
    JADE_ASSERT(entry.event_id == event_id);
    JADE_ASSERT(entry.instance == instance);
    // remove from map
    int ret = wally_map_remove_integer(&_event_handlers, entry_id);
    JADE_ASSERT(ret == WALLY_OK);
    // release event handler mutex
    if (pthread_mutex_unlock(&_event_handlers_mutex)) {
        JADE_ABORT();
    }
    return ESP_OK;
}

#else

esp_err_t esp_event_loop_create_default(void) { return ESP_OK; }

esp_err_t esp_event_post(
    esp_event_base_t event_base, int32_t event_id, void* event_data, size_t event_data_size, TickType_t ticks_to_wait)
{
    return ESP_OK;
}

esp_err_t esp_event_handler_instance_register(esp_event_base_t event_base, int32_t event_id,
    esp_event_handler_t event_handler, void* event_handler_arg, esp_event_handler_instance_t* instance)
{
    return ESP_OK;
}

esp_err_t esp_event_handler_unregister(esp_event_base_t event_base, int32_t event_id, esp_event_handler_t event_handler)
{
    return ESP_OK;
}

esp_err_t esp_event_handler_instance_unregister(
    esp_event_base_t event_base, int32_t event_id, esp_event_handler_instance_t instance)
{
    return ESP_OK;
}

#endif
