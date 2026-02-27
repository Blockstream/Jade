#ifndef _LIBJADE_ESP_EVENT_H_
#define _LIBJADE_ESP_EVENT_H_ 1

#include <esp_err.h>
#include <freertos/task.h>

typedef const char* esp_event_base_t;
typedef void (*esp_event_handler_t)(
    void* event_handler_arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
typedef void* esp_event_handler_instance_t;

typedef void* esp_event_loop_handle_t;

#define ESP_EVENT_DECLARE_BASE(id) extern esp_event_base_t const id
#define ESP_EVENT_DEFINE_BASE(id) esp_event_base_t const id = #id

#define ESP_EVENT_ANY_BASE NULL
#define ESP_EVENT_ANY_ID -1

esp_err_t esp_event_loop_create_default(void);

esp_err_t esp_event_loop_delete_default(void);

esp_err_t esp_event_post(
    esp_event_base_t event_base, int32_t event_id, void* event_data, size_t event_data_size, TickType_t ticks_to_wait);

esp_err_t esp_event_handler_instance_register(esp_event_base_t event_base, int32_t event_id,
    esp_event_handler_t event_handler, void* event_handler_arg, esp_event_handler_instance_t* instance);

esp_err_t esp_event_handler_instance_unregister(
    esp_event_base_t event_base, int32_t event_id, esp_event_handler_instance_t instance);

#endif // _LIBJADE_ESP_EVENT_H_
