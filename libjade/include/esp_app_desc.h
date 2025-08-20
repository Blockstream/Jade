#ifndef _LIBJADE_ESP_APP_DESC_H_
#define _LIBJADE_ESP_APP_DESC_H_ 1

typedef struct esp_app_desc {
    char version[32];
    int secure_version;
} esp_app_desc_t;

#endif // _LIBJADE_ESP_APP_DESC_H_
