#ifndef __LIBJADE_ESP_LOG__
#define __LIBJADE_ESP_LOG__ 1

#include <stdio.h>

typedef enum {
    ESP_LOG_VERBOSE = 0,
    ESP_LOG_DEBUG = 1,
    ESP_LOG_INFO = 2,
    ESP_LOG_WARN = 3,
    ESP_LOG_ERROR = 4,
    ESP_LOG_NONE = 5
} esp_log_level_t;

extern esp_log_level_t _libjade_log_level;

#define ESP_LOGD(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_DEBUG)                                                                       \
            fprintf(stderr, f ":" fmt "\n", __VA_ARGS__);                                                              \
    } while (0)
#define ESP_LOGI(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_INFO)                                                                        \
            fprintf(stderr, f ":" fmt "\n", __VA_ARGS__);                                                              \
    } while (0)
#define ESP_LOGW(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_WARN)                                                                        \
            fprintf(stderr, f ":" fmt "\n", __VA_ARGS__);                                                              \
    } while (0)
#define ESP_LOGE(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_ERROR)                                                                       \
            fprintf(stderr, f ":" fmt "\n", __VA_ARGS__);                                                              \
    } while (0)

static inline void esp_log_level_set(const char* tag, esp_log_level_t level)
{
    // Do nothing, so our internal call to this function doesn't
    // overwrite the callers desired log level
}

#endif // __LIBJADE_ESP_LOG__
