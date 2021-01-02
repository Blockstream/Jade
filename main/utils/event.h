#ifndef UTILS_EVENT_H_
#define UTILS_EVENT_H_

#include <esp_event.h>

#define ESP_NO_EVENT 0xFF

ESP_EVENT_DECLARE_BASE(JADE_EVENT);

enum jade_events {
    CAMERA_EXIT,
    SIGN_TX_ACCEPT_OUTPUTS,
    SIGN_TX_DECLINE,
};

typedef struct wait_event_data_t wait_event_data_t;

void sync_wait_event_handler(void* handler_arg, esp_event_base_t base, int32_t id, void* event_data);

wait_event_data_t* make_wait_event_data();
void free_wait_event_data(wait_event_data_t* data);

esp_err_t sync_wait_event(esp_event_base_t event_base, int32_t event_id, wait_event_data_t* wait_event_data,
    esp_event_base_t* trigger_event_base, int32_t* trigger_event_id, void** trigger_event_data, TickType_t max_wait);

#endif /* UTILS_EVENT_H_ */
