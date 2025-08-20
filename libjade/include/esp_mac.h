#ifndef _LIBJADE_ESP_MAC_H_
#define _LIBJADE_ESP_MAC_H_ 1

#include <esp_err.h>

esp_err_t esp_efuse_mac_get_default(uint8_t* out);

#endif // _LIBJADE_ESP_MAC_H_
