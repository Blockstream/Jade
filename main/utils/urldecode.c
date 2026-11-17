#ifndef AMALGAMATED_BUILD
#include "urldecode.h"
#include "../jade_assert.h"
#include "util.h"

#include <stdio.h>

static char map_char(char c)
{
    // Helper to map url-encoded %-escaped character
    JADE_ASSERT(safe_isxdigit(c));

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

// Core implementation of URL decoding.
// Destination buffer, 'dest' is allowed to be NULL for "dry run" processing (source validation).
// Optional 'check_fn', if not NULL, is called for each decoded character for additional validation.
static bool try_urldecode(
    const char* src, const size_t src_len, char* dest, const size_t dest_len, int (*check_fn)(int))
{
    // We don't use assertions to give more flexibility for using this function to validate encoded
    // string with uncertain arguments (like validating optional parameters that are absent atm).
    if (!src || !src_len || !dest_len) {
        return false;
    }

    const char* src_end = src + src_len;
    char* dest_start = dest;
    size_t decoded_len = 0;

    // Handle both nul-terminated and length-specified string data.
    // Nul-terminated string is accepted only if it has no nonzero characters after the terminator.
    while (src < src_end) {
        if (*src == '\0') {
            // Verify that a nul-terminated string is nul-padded
            while (src < src_end) {
                if (*src++ != '\0') {
                    return false;
                }
            }
            break; // terminate processing of input string
        }

        if (decoded_len + 1 == dest_len) {
            // Destination insufficient - need last location for nul-terminator
            return false;
        }

        int decoded;
        if (*src == '%') {
            // Ensure we have at least 2 more characters in the input string and both are hex digits
            if ((src_end - src <= 2) || !safe_isxdigit(src[1]) || !safe_isxdigit(src[2])) {
                return false;
            }

            // Fetch 3 input characters and hex decode them into a single output character
            decoded = (16 * map_char(src[1])) + map_char(src[2]);
            src += 3;
        } else if (*src == '+') {
            // Encoded <space>
            decoded = ' ';
            ++src;
        } else {
            // Assign "as is" (avoiding signed promotion)
            decoded = (unsigned char)*src++;
        }

        // Ensure the character falls in the allowed range: <space>...~
        if (decoded < 0x20 || decoded > 0x7e) {
            // Reject embedded nul, control characters, non-ASCII bytes and DEL
            return false;
        }

        // Use callback function for filtering decoded character if given
        if (check_fn && !check_fn(decoded)) {
            return false; // rejected by caller-provided check function: fail
        }

        // Copy decoded character into output buffer if we aren't in the "dry run" mode
        if (dest) {
            *dest++ = decoded;
        }
        ++decoded_len;
    }

    // Sanity check: ensure all input characters are processed
    JADE_ASSERT(src == src_end);
    // Sanity check: ensure we didn't overrun the output buffer
    JADE_ASSERT(decoded_len < dest_len);
    // Nul-terminate the output string if we aren't in the "dry run" mode
    if (dest) {
        // Sanity check: destination pointer is consistent with decoded counter
        JADE_ASSERT(dest == dest_start + decoded_len);
        *dest = '\0';
    }
    return true;
}

bool urldecode(const char* src, const size_t src_len, char* dest, const size_t dest_len)
{
    JADE_ASSERT(src);
    JADE_ASSERT(src_len);
    JADE_ASSERT(dest);
    JADE_ASSERT(dest_len);
    return try_urldecode(src, src_len, dest, dest_len, NULL);
}

bool urlencode(const char* src, const size_t src_len, char* dest, const size_t dest_len)
{
    JADE_ASSERT(src);
    JADE_ASSERT(src_len);
    JADE_ASSERT(dest);
    JADE_ASSERT(dest_len);

    const char* src_end = src + src_len;
    const char* dest_end = dest + dest_len;

    while (src < src_end) {
        if (dest_end - dest < 2) {
            // Destination insufficient - need at least 1 char for encoding and 1 for nul-terminator.
            // Truncate (terminate) here and return false.
            *dest = '\0';
            return false;
        }

        if (safe_isalnum(*src) || *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            // Non-encoded character - copy across
            *dest++ = *src++;
        } else if (*src == ' ') {
            // Space is encoded as '+'
            *dest++ = '+';
            ++src;
        } else {
            if (dest_end - dest < 4) {
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

bool is_valid_urlencoding(const char* src, const size_t src_len, const size_t max_len, int (*check_fn)(int))
{
    JADE_ASSERT(max_len);
    return try_urldecode(src, src_len, NULL, max_len, check_fn);
}

#endif // AMALGAMATED_BUILD
