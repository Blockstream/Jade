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

#ifdef CONFIG_LOG_DEFAULT_LEVEL_NONE
#define _libjade_log_level ESP_LOG_NONE
#else
extern esp_log_level_t _libjade_log_level;
#endif

#define ESP_LOGD(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_DEBUG)                                                                       \
            fprintf(stderr, "DEBUG:%s:" fmt "\n", f, __VA_ARGS__);                                                     \
    } while (0)
#define ESP_LOGI(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_INFO)                                                                        \
            fprintf(stderr, "INFO:%s:" fmt "\n", f, __VA_ARGS__);                                                      \
    } while (0)
#define ESP_LOGW(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_WARN)                                                                        \
            fprintf(stderr, "WARN:%s:" fmt "\n", f, __VA_ARGS__);                                                      \
    } while (0)
#define ESP_LOGE(f, fmt, ...)                                                                                          \
    do {                                                                                                               \
        if (_libjade_log_level <= ESP_LOG_ERROR)                                                                       \
            fprintf(stderr, "ERROR:%s:" fmt "\n", f, __VA_ARGS__);                                                     \
    } while (0)

#ifndef CONFIG_LOG_DEFAULT_LEVEL_NONE
static inline void esp_log_level_set(const char* tag, esp_log_level_t level)
{
    // Do nothing, so our internal call to this function doesn't
    // overwrite the callers desired log level.
    // We only provide an implementation when DEFAULT_LEVEL_NONE is not set,
    // so that any use of this function without that guard can be caught
    // at compile time.
}
#endif

#endif // __LIBJADE_ESP_LOG__
