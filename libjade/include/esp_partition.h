#ifndef __LIBJADE_ESP_PARTITION__
#define __LIBJADE_ESP_PARTITION__ 1

#include <esp_err.h>

typedef struct esp_partition {
    size_t size;
} esp_partition_t;

typedef struct esp_image_header {
    int chip_id;
} esp_image_header_t;
typedef void* esp_image_segment_header_t;

static inline esp_err_t esp_partition_read(const esp_partition_t* p, size_t offset, void* dst, size_t size)
{
    return ESP_OK;
}

// TODO: This belongs in esp_efuse.h if we ever want to mock it properly
static inline bool esp_efuse_check_secure_version(uint32_t version) { return true; }
#endif // __LIBJADE_ESP_PARTITION__
