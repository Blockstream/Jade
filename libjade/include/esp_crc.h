#ifndef _LIBJADE_ESP_CRC_H
#define _LIBJADE_ESP_CRC_H 1

#include <zlib.h>

static inline uint32_t esp_crc32_le(uint32_t crc, uint8_t const* buf, uint32_t len) { return crc32(crc, buf, len); }

#endif // _LIBJADE_ESP_CRC_H
