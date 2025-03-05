#ifndef JADE_LOG_H_
#define JADE_LOG_H_

#include <esp_log.h>

#define JADE_LOGD(fmt, ...) ESP_LOGD(__FILE_NAME__, "%d: " fmt, __LINE__, ##__VA_ARGS__)

#define JADE_LOGE(fmt, ...) ESP_LOGE(__FILE_NAME__, "%d: " fmt, __LINE__, ##__VA_ARGS__)

#define JADE_LOGI(fmt, ...) ESP_LOGI(__FILE_NAME__, "%d: " fmt, __LINE__, ##__VA_ARGS__)

#define JADE_LOGW(fmt, ...) ESP_LOGW(__FILE_NAME__, "%d: " fmt, __LINE__, ##__VA_ARGS__)

#endif
