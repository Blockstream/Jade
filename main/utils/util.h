#ifndef UTIL_H_
#define UTIL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jade_assert.h"

#ifdef CONFIG_IDF_TARGET_ESP32S3
#include <dsps_mem.h>
#define jmemcpy dsps_memcpy_aes3
#define jmemset dsps_memset_aes3
#else
#include <string.h>
#define jmemcpy memcpy
#define jmemset memset
#endif

static inline uint16_t min_u16(uint16_t a, uint16_t b) { return a < b ? a : b; }

static inline const char* make_empty_none(const char* pstr) { return (!pstr || *pstr == '\0') ? "<None>" : pstr; }

static inline void reverse(uint8_t* dest, const uint8_t* src, const size_t len)
{
    JADE_ASSERT(dest);
    JADE_ASSERT(src);

    for (size_t i = 0; i < len; ++i) {
        dest[i] = src[len - 1 - i];
    }
}

static inline void uint32_to_be(const uint32_t val, uint8_t* buffer)
{
    JADE_ASSERT(buffer);

    buffer[0] = (val >> 24) & 0xFF;
    buffer[1] = (val >> 16) & 0xFF;
    buffer[2] = (val >> 8) & 0xFF;
    buffer[3] = val & 0xFF;
}
static inline void uint32_to_le(const uint32_t val, uint8_t* buffer)
{
    JADE_ASSERT(buffer);

    buffer[0] = val & 0xFF;
    buffer[1] = (val >> 8) & 0xFF;
    buffer[2] = (val >> 16) & 0xFF;
    buffer[3] = (val >> 24) & 0xFF;
}

static inline bool string_all(const char* s, int (*fntest)(int))
{
    JADE_ASSERT(s);
    JADE_ASSERT(fntest);

    while (*s) {
        if (!fntest(*s++)) {
            return false;
        }
    }
    return true;
}

static inline void map_string(char* s, int (*fnmap)(int))
{
    JADE_ASSERT(s);
    JADE_ASSERT(fnmap);

    while (*s) {
        *s = fnmap(*s);
        ++s;
    }
}

// Bip32 path utils
static inline bool ishardened(const uint32_t n) { return n & 0x80000000; }
static inline uint32_t harden(const uint32_t n) { return n | 0x80000000; }
static inline uint32_t unharden(const uint32_t n) { return n & ~0x80000000; }

// Return the first index where all remaining elements are unhardened.
// A return value >= `path_len` indicates the entire path is hardened.
static inline size_t path_get_unhardened_tail_index(const uint32_t* path, const size_t path_len)
{
    size_t path_tail_start = 0;
    for (size_t i = 0; i < path_len; ++i) {
        if (ishardened(path[i])) {
            path_tail_start = i + 1;
        }
    }
    return path_tail_start;
}

#endif /* UTIL_H_ */
