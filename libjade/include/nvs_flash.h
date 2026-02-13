#ifndef _LIBJADE_NVS_FLASH_H_
#define _LIBJADE_NVS_FLASH_H_ 1

#include <esp_err.h>

typedef int nvs_open_mode_t;
#define NVS_READONLY 0
#define NVS_READWRITE 1

typedef struct wally_map* nvs_handle_t;
typedef nvs_handle_t nvs_handle;

typedef struct nvs_iterator {
    struct wally_map* m;
    size_t idx;
}* nvs_iterator_t;

#define NVS_DEFAULT_PART_NAME ""

typedef enum nvs_type { NVS_TYPE_STR, NVS_TYPE_BLOB } nvs_type_t;

#define NVS_NS_NAME_MAX_SIZE 16
#define NVS_KEY_NAME_MAX_SIZE 16

typedef struct nvs_entry_info {
    char namespace_name[NVS_NS_NAME_MAX_SIZE];
    char key[NVS_KEY_NAME_MAX_SIZE];
    nvs_type_t type;
} nvs_entry_info_t;

typedef struct nvs_stats {
    size_t used_entries;
    size_t free_entries;
} nvs_stats_t;

esp_err_t nvs_flash_init(void);
esp_err_t nvs_flash_erase(void);
esp_err_t nvs_get_stats(const char* part_name, nvs_stats_t* nvs_stats);

esp_err_t nvs_open(const char* ns, nvs_open_mode_t open_mode, nvs_handle_t* out_handle);

static inline void nvs_close(nvs_handle_t handle) {}

static inline esp_err_t nvs_commit(nvs_handle_t handle) { return ESP_OK; }

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length);

esp_err_t nvs_set_str(nvs_handle_t handle, const char* key, const char* value);
esp_err_t nvs_get_str(nvs_handle_t handle, const char* key, char* out_value, size_t* length);

esp_err_t nvs_set_u32(nvs_handle_t handle, const char* key, uint32_t value);
esp_err_t nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out_value);

esp_err_t nvs_entry_find(const char* part_name, const char* ns, nvs_type_t type, nvs_iterator_t* output_iterator);
esp_err_t nvs_entry_next(nvs_iterator_t* iterator);
esp_err_t nvs_entry_info(const nvs_iterator_t iterator, nvs_entry_info_t* out_info);
void nvs_release_iterator(nvs_iterator_t iterator);

#endif // _LIBJADE_NVS_FLASH_H_
