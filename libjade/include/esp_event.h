#ifndef _LIBJADE_ESP_EVENT_H_
#define _LIBJADE_ESP_EVENT_H_ 1

#include <esp_err.h>

typedef const char* esp_event_base_t;
typedef void* esp_event_handler_t;
typedef void* esp_event_handler_instance_t;

#define ESP_EVENT_DECLARE_BASE(id) extern esp_event_base_t const id
#define ESP_EVENT_DEFINE_BASE(id) esp_event_base_t const id = #id

#define ESP_EVENT_ANY_BASE NULL
#define ESP_EVENT_ANY_ID -1

#endif // _LIBJADE_ESP_EVENT_H_
