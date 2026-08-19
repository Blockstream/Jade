#include "selfcheck.h"

typedef struct {
    const char* cbor_hex;
    bool expected_ok;
} cbor_test_t;

static const cbor_test_t cbor_tests[] = {
    // String with length exceeding the input buffer
    { "5AFFFFFFFF", false }
};

static bool test_invalid_cbor(void)
{
    static unsigned char cbor_bytes[8 * 1024];

    for (size_t i = 0; i < sizeof(cbor_tests) / sizeof(cbor_tests[0]); ++i) {
        const cbor_test_t* test = &cbor_tests[i];
        size_t written;
        int ret = wally_hex_to_bytes(test->cbor_hex, cbor_bytes, sizeof(cbor_bytes), &written);
        if (ret != WALLY_OK || written > sizeof(cbor_bytes)) {
            return false;
        }

        CborParser parser;
        CborValue result;
        if (rpc_untrusted_parser_init(cbor_bytes, written, &parser, &result) != test->expected_ok) {
            return false;
        }

        const uint8_t* bytes;
        size_t bytes_len;
        if (bcur_parse_bytes(cbor_bytes, written, &bytes, &bytes_len) != test->expected_ok) {
            return false;
        }

        if (test->expected_ok && (!bytes || !bytes_len)) {
            return false;
        } else if (!test->expected_ok && (bytes || bytes_len)) {
            return false;
        }
    }
    return true;
}

static bool test_parser_recursion_limit(void)
{
    JADE_STATIC_ASSERT(CBOR_PARSER_MAX_RECURSIONS > 0);

    enum { MIN_DEPTH = CBOR_PARSER_MAX_RECURSIONS - 1, MAX_DEPTH = CBOR_PARSER_MAX_RECURSIONS + 1 };
    uint8_t cbor[MAX_DEPTH + 1];

    for (size_t depth = MIN_DEPTH; depth <= MAX_DEPTH; ++depth) {
        // A single-item array at each level, terminated by a null leaf:
        // [[[...[null]...]]]
        memset(cbor, CborArrayType | 1, depth); // one element arrays
        cbor[depth] = CborNullType;

        CborParser parser;
        CborValue root;
        const CborError init_res = cbor_parser_init(cbor, depth + 1, CborValidateBasic, &parser, &root);
        JADE_ASSERT(init_res == CborNoError);
        JADE_ASSERT(cbor_value_is_array(&root));

        const CborError expected_err = depth <= CBOR_PARSER_MAX_RECURSIONS ? CborNoError : CborErrorNestingTooDeep;
        const CborError err = cbor_value_validate_basic(&root);
        const char* err_text = err == CborNoError ? "ok" : cbor_error_string(err);
        JADE_LOGD("Validating CBOR with nesting depth %zu: %s", depth, err_text);
        if (err != expected_err) {
            JADE_LOGE("Failed CBOR validation case with nesting depth %zu", depth);
            return false;
        }
    }

    return true;
}

bool debug_selfcheck(jade_process_t* process)
{
    if (!test_invalid_cbor()) {
        FAIL();
    }
    if (!test_parser_recursion_limit()) {
        FAIL();
    }
    return true;
}
