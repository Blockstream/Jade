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

// flip the order of the bytes in-place
static inline void reverse_in_place(uint8_t* buf, size_t len)
{
    JADE_ASSERT(buf);

    for (uint8_t *c1 = buf, *c2 = buf + len - 1; c1 < c2; ++c1, --c2) {
        const uint8_t tmp = *c1;
        *c1 = *c2;
        *c2 = tmp;
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

// The length of the required buffer to hold 'len' characters
// with a nul-terminator injected every 'wordlen' characters, and
// at the very end.  eg. for "abcdefhij\0" -> "abc\0def\0ghi\0j\0"
#define SPLIT_TEXT_LEN(len, wordlen) (len + (len / wordlen) + 1)

// Helper to copy text from one buffer to another, where the destination has terminators every
// 'wordlen' chars, eg: "abcdefghi\0" -> "abc\0def\0ghi\0j\0"
// output 'num_words' is number of 'words' written - eg. 4
// output 'written' is number of bytes written, including all '\0's - eg. 14
void split_text(
    const char* src, size_t len, size_t wordlen, char* output, size_t output_len, size_t* num_words, size_t* written);

// Parse a uint64 from a string. Allows leading zeros but no non-digit chars
bool parse_uint64(const char* str, size_t str_len, uint64_t* value_out);

// As for parse_uint64 but for 32 bit integers
bool parse_uint32(const char* str, size_t str_len, uint32_t* value_out);

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

bool is_potential_green_user_path(const uint32_t* path, size_t path_len, uint32_t* subaccount_out);
bool is_potential_green_recovery_path(const uint32_t* path, size_t path_len);
bool is_potential_green_server_path(const uint32_t* path, size_t path_len, uint32_t* subaccount_out);

// Helper function to convert a base32 string to binary, returns 0 on failure
size_t base32_to_bin(const char* b32_str, size_t b32_str_len, uint8_t* bin, size_t bin_len);
// Helper function to convert binary data to a base32 string, padding optional
bool bin_to_base32(const uint8_t* bin, size_t bin_len, char* b32_str, size_t b32_str_len, bool use_padding);

#endif /* UTIL_H_ */
