#ifndef _LIBJADE_ESP_OTA_OPS_H_
#define _LIBJADE_ESP_OTA_OPS_H_ 1

#include <esp_err.h>

typedef void* esp_partition_t;
typedef int esp_ota_img_states_t;

#define ESP_OTA_IMG_PENDING_VERIFY 1

static inline const esp_partition_t* esp_ota_get_running_partition(void) { return NULL; }
static inline const esp_partition_t* esp_ota_get_boot_partition(void) { return NULL; }
static inline esp_err_t esp_ota_mark_app_valid_cancel_rollback(void) { return ESP_FAIL; };

static inline esp_err_t esp_ota_get_partition_description(const esp_partition_t* p, esp_app_desc_t* out)
{
    return ESP_FAIL;
}

static inline esp_err_t esp_ota_get_state_partition(const esp_partition_t* p, esp_ota_img_states_t* out)
{
    return ESP_FAIL;
}
#endif // _LIBJADE_ESP_OTA_OPS_H_
