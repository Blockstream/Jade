#ifndef UTIL_H_
#define UTIL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#endif /* UTIL_H_ */
