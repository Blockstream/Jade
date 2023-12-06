#include "urldecode.h"
#include "../jade_assert.h"

#include <ctype.h>

static inline char map_char(char c)
{
    // Helper to map url-encoded %-escaped character
    JADE_ASSERT(isxdigit(c));

    if (c >= 'a') {
        c -= ('a' - 'A');
    }

    if (c >= 'A') {
        c -= ('A' - 10);
    } else {
        c -= '0';
    }

    return c;
}

// Simple urldecode function - any triple that looks like "%,hex,hex" is replaced by the character
// specified, a '+' is replaced by a space, and anything else is copied verbatim.
// The output string is always nul-terminated (although the input need not be).
bool urldecode(const char* src, const size_t src_len, char* dest, const size_t dest_len)
{
    JADE_ASSERT(src);
    JADE_ASSERT(src_len);
    JADE_ASSERT(dest);
    JADE_ASSERT(dest_len);

    const char* src_end = src + src_len;
    const char* dest_end = dest + dest_len;

    // Handle both terminated and length-specified string data
    while (src < src_end && *src) {
        if (dest == dest_end - 1) {
            // Destination insufficient - need last location for nul-terminator.
            // Truncate (terminate) here and return false.
            *dest = '\0';
            return false;
        }

        const unsigned char c1 = src[1];
        const unsigned char c2 = src[2];

        if ((*src == '%') && (src < src_end - 2) && isxdigit(c1) && isxdigit(c2)) {
            // Encoded hex character
            *dest++ = (16 * map_char(c1)) + map_char(c2);
            src += 3;
        } else if (*src == '+') {
            // Encoded <space>
            *dest++ = ' ';
            ++src;
        } else {
            // Copy across
            *dest++ = *src++;
        }
    }

    JADE_ASSERT(dest < dest_end);
    *dest = '\0';
    return true;
}
