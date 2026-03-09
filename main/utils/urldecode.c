#ifndef AMALGAMATED_BUILD
#include "urldecode.h"
#include "../jade_assert.h"

#include <ctype.h>
#include <stdio.h>

static char map_char(char c)
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

// Simple urlencode function - special chars are replaced by %XX, space is replaced by '+',
// and anything else is copied verbatim.
// The output string is always nul-terminated (although the input need not be).
bool urlencode(const char* src, const size_t src_len, char* dest, const size_t dest_len)
{
    JADE_ASSERT(src);
    JADE_ASSERT(src_len);
    JADE_ASSERT(dest);
    JADE_ASSERT(dest_len);

    const char* src_end = src + src_len;
    const char* dest_end = dest + dest_len;

    while (src < src_end) {
        if (dest > dest_end - 2) {
            // Destination insufficient - need at least 1 char for encoding and 1 for nul-terminator.
            // Truncate (terminate) here and return false.
            *dest = '\0';
            return false;
        }

        if (isalnum((unsigned char)*src) || *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            // Non-encoded character - copy across
            *dest++ = *src++;
        } else if (*src == ' ') {
            // Space is encoded as '+'
            *dest++ = '+';
            ++src;
        } else {
            if (dest > dest_end - 4) {
                // Destination insufficient - need 3 chars for encoding and 1 for nul-terminator.
                // Truncate (terminate) here and return false.
                *dest = '\0';
                return false;
            }

            // Encode as %XX
            snprintf(dest, dest_end - dest, "%%%02X", (unsigned char)*src);
            ++src;
            dest += 3;
        }
    }

    JADE_ASSERT(dest < dest_end);
    *dest = '\0';
    return true;
}
#endif // AMALGAMATED_BUILD
