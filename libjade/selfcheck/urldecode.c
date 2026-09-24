#include <ctype.h>
#include <limits.h>
#include <stdio.h>

#include "main/utils/urldecode.h"
#include "selfcheck.h"

#include <wally_core.h>

typedef struct {
    const char* name;
    const char* src;
    size_t src_len;
    size_t max_len;
    int (*check_fn)(int);
    uint8_t flags;
    const char* expected_decoded;
} urldecode_test_t;

enum {
    INVALID = 0, // Test case is expected to fail validation
    VALID = (1 << 0), // Test case is expected to pass validation
    FAIL_DECODE = (1 << 1), // Test case is expected to fail decoding
    PASS_DECODE = (1 << 2) // Test case is expected to pass decoding
};

// No check function provided, alias for NULL
#define NO_FN NULL

// Length-specified strings
const char bounded_str[] = { 'A', '%', '3', '1', 'Z' }; // decodes to "A1Z"
const char all_nuls[] = { '\0', '\0' };
const char padded_nuls[] = { 'a', 'b', 'c', '\0', '\0', '\0' };
const char embedded_nul[] = { 'a', 'b', 'c', '\0', 'd', 'e', 'f' };
const char percent_padded_nuls[] = { '%', '\0', '\0' };
const char short_percent_padded_nul[] = { '%', '2', '\0' };

// clang-format off
static const urldecode_test_t urldecode_tests[] = {
    { "valid: printable characters", "abc-_.~", strlen("abc-_.~"), 8, NO_FN, VALID | PASS_DECODE, "abc-_.~" },
    { "valid: space and mixed-case hex", "a%20b+%7a%5A", strlen("a%20b+%7a%5A"), 7, NO_FN, VALID | PASS_DECODE, "a b zZ" },
    { "valid: printable hex with isprint", "%41%4a%4A", strlen("%41%4a%4A"), 4, isprint, VALID | PASS_DECODE, "AJJ" },
    { "valid: length-specified source", bounded_str, sizeof(bounded_str), 4, isprint, VALID | PASS_DECODE, "A1Z" },
    { "valid: all-nul source padding", all_nuls, sizeof(all_nuls), 1, NO_FN, VALID | PASS_DECODE, "" },
    { "valid: nul-padded source", padded_nuls, sizeof(padded_nuls), sizeof(padded_nuls), NO_FN, VALID | PASS_DECODE, "abc" },
    { "invalid-nul: encoded nul", "%00abc", strlen("%00abc"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-nul: encoded nul", "ab%00c", strlen("ab%00c"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-nul: encoded nul", "ab%00", strlen("ab%00"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-nul: embedded nul", embedded_nul, sizeof(embedded_nul), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-char: encoded low control", "a\x01" "bc", strlen("a\x01" "bc"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-char: encoded high control", "abc\x1F" "de", strlen("abc\x1F" "de"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-char: encoded del", "abc\x7F", strlen("abc\x7F"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-char: encoded utf-8 lead byte", "a\x80" "bc", strlen("a\x80" "bc"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-char: encoded high byte", "ab\xFF" "cd", strlen("ab\xFF" "cd"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-hex: encoded low control", "a%01bc", strlen("a%01bc"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-hex: encoded high control", "abc%1Fde", strlen("abc%1Fde"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-hex: encoded del", "abc%7F", strlen("abc%7F"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-hex: encoded utf-8 lead byte", "a%80bc", strlen("a%80bc"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-hex: encoded high byte", "ab%FFcd", strlen("ab%FFcd"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: bare percent", "%", strlen("%"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: bare percent before nul padding", percent_padded_nuls, sizeof(percent_padded_nuls), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: short percent encoding", "%2", strlen("%2"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: short percent before nul padding", short_percent_padded_nul, sizeof(short_percent_padded_nul), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: bad first hex digit", "%x2", strlen("%x2"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: bad second hex digit", "%2x", strlen("%2x"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "invalid-percent: bad hex digits", "%xx", strlen("%xx"), 8, NO_FN, INVALID | FAIL_DECODE, "" },
    { "user-check: valid string filtered by isupper", "TEST", strlen("TEST"), 8, isupper, VALID | PASS_DECODE, "TEST" },
    { "user-check: letter rejected by isupper", "TEsT", strlen("TEsT"), 8, isupper, INVALID | PASS_DECODE, "TEsT" },
    { "user-check: valid string with percent filtered by isupper", "TE%53T", strlen("TE%53T"), 8, isupper, VALID | PASS_DECODE, "TEST" },
    { "user-check: percent-encoded letter rejected by isupper", "TE%73T", strlen("TE%73T"), 8, isupper, INVALID | PASS_DECODE, "TEsT" },
    { "input-buffer: null source", NULL, 1, 8, NO_FN, INVALID, "" },
    { "input-buffer: zero source length", "", 0, 8, NO_FN, INVALID, "" },
    { "output-buffer: output buffer too short", "abc", strlen("abc"), 3, NO_FN, INVALID | FAIL_DECODE, "" },
    { "output-buffer: output buffer just right", "abc", strlen("abc"), 4, NO_FN, VALID | PASS_DECODE, "abc" }
};
// clang-format on

static bool check_urldecode_case(const urldecode_test_t* test)
{
    JADE_ASSERT(test);
    // Sanity check: if decoding is tested it's expected to either pass it or fail it, but not both
    JADE_ASSERT(!((test->flags & PASS_DECODE) && (test->flags & FAIL_DECODE)));

    if (test->src) {
        if (string_n_all(test->src, test->src_len, isprint)) {
            JADE_LOGI("URL decode %s: \"%.*s\"", test->name, (int)test->src_len, test->src);
        } else {
            char* src_hex = NULL;
            JADE_WALLY_VERIFY(wally_hex_from_bytes((const unsigned char*)test->src, test->src_len, &src_hex));
            JADE_LOGI("URL decode %s: %s (hex)", test->name, src_hex);
            JADE_WALLY_VERIFY(wally_free_string(src_hex));
        }
    } else {
        JADE_LOGI("URL decode %s: <NULL>", test->name);
    }

    const bool expected_encoding_valid = (test->flags & VALID) != 0;
    const bool valid = is_valid_urlencoding(test->src, test->src_len, test->max_len, test->check_fn);
    if (valid != expected_encoding_valid) {
        JADE_LOGE("is_valid_urlencoding() failed case: %s", test->name);
        return false;
    }

    // Check if this test case is supposed to test urldecode()
    if (!(test->flags & (PASS_DECODE | FAIL_DECODE))) {
        return true; // skip urldecode()
    }

    char decoded[32];
    JADE_ASSERT(test->max_len <= sizeof(decoded));
    memset(decoded, 0, sizeof(decoded));
    const bool expected_decode_valid = (test->flags & PASS_DECODE) != 0;
    const bool decode_valid = urldecode(test->src, test->src_len, decoded, test->max_len);
    if (decode_valid != expected_decode_valid) {
        JADE_LOGE("urldecode() failed case: %s", test->name);
        return false;
    }
    if (decode_valid && strcmp(decoded, test->expected_decoded) != 0) {
        JADE_LOGE("urldecode() decoded '%s', expected '%s'", decoded, test->expected_decoded);
        return false;
    }

    return true;
}

static bool test_all_characters(void)
{
    static const char hex[] = "0123456789ABCDEF";
    const int allowed_min = 0x20; // space
    const int allowed_max = 0x7e; // tilde
    urldecode_test_t test;

    // Try every bare character (skipping '\0' as it's interpreted as a terminator)
    for (int c = 1; c <= UCHAR_MAX; ++c) {
        if (c == '%') {
            continue; // skip escape character (tested separately)
        }
        const char encoded[] = { (char)c, '\0' };
        const char decoded[] = { c == '+' ? ' ' : (char)c, '\0' };
        if (c >= allowed_min && c <= allowed_max) {
            test = (urldecode_test_t){ "valid-char: all values", encoded, 1, 8, NO_FN, VALID | PASS_DECODE, decoded };
        } else {
            test = (urldecode_test_t){ "invalid-char: all values", encoded, 1, 8, NO_FN, INVALID | FAIL_DECODE, "" };
        }
        if (!check_urldecode_case(&test)) {
            return false;
        }
    }

    // Try every percent-encoded character
    for (int c = 0; c <= UCHAR_MAX; ++c) {
        const char encoded[] = { '%', hex[c >> 4], hex[c & 0x0f], '\0' };
        const char decoded[] = { (char)c, '\0' };
        if (c >= allowed_min && c <= allowed_max) {
            test = (urldecode_test_t){ "valid-hex: all values", encoded, 3, 8, NO_FN, VALID | PASS_DECODE, decoded };
        } else {
            test = (urldecode_test_t){ "invalid-hex: all values", encoded, 3, 8, NO_FN, INVALID | FAIL_DECODE, "" };
        }
        if (!check_urldecode_case(&test)) {
            return false;
        }
    }

    return true;
}

bool test_urldecode(void)
{
    JADE_LOGI("Testing validator and decoder for URL-encoded strings");

    for (size_t i = 0; i < sizeof(urldecode_tests) / sizeof(urldecode_tests[0]); ++i) {
        if (!check_urldecode_case(&urldecode_tests[i])) {
            return false;
        }
    }

    return test_all_characters();
}

bool debug_selfcheck(jade_process_t* process)
{
    if (!test_urldecode()) {
        FAIL();
    }
    return true;
}
