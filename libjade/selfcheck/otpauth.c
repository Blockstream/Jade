#include "main/otpauth.h"
#include "main/utils/urldecode.h"
#include "selfcheck.h"

// From main/process/register_otp.c
int register_otp_migrate_string(const char* otp_migrate_uri, size_t uri_len, const char** errmsg);

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

// Standard URI prefix for otpauth-migration uris
#define URI_PREFIX "otpauth-migration://offline?data="

// Single record with the default (TOTP, SHA1, 6 digit) parameters and no name/issuer fields
#define DATA_DEFAULT_RECORD "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACEAE%3D"
#define URI_DEFAULT_RECORD URI_PREFIX DATA_DEFAULT_RECORD
// Valid uri with 0 records (only the version field)
#define URI_NO_RECORDS URI_PREFIX "EAE%3D"
// Data parameter which is not base64
#define URI_DATA_NOT_BASE64 URI_PREFIX "!!!"

// Valid uri with the maximum number of records
#define URI_MULTIPLE_RECORDS                                                                                           \
    URI_PREFIX                                                                                                         \
    "CiUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgdyZWNvcmQwIAEoATACCiUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgdyZWNvcmQxIAEoATACCiUKFDEy" \
    "MzQ1Njc4OTAxMjM0NTY3ODkwEgdyZWNvcmQyIAEoATACCiUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgdyZWNvcmQzIAEoATACCiUKFDEyMzQ1Njc4" \
    "OTAxMjM0NTY3ODkwEgdyZWNvcmQ0IAEoATACCiUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgdyZWNvcmQ1IAEoATACCiUKFDEyMzQ1Njc4OTAxMjM0" \
    "NTY3ODkwEgdyZWNvcmQ2IAEoATACCiUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgdyZWNvcmQ3IAEoATACEAE%3D"
// More records than the allowed maximum
#define URI_TOO_MANY_RECORDS                                                                                           \
    URI_PREFIX                                                                                                         \
    "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkw" \
    "IAEoATACChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4OTAxMjM0" \
    "NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATACChwKFDEyMzQ1Njc4" \
    "OTAxMjM0NTY3ODkwIAEoATACEAE%3D"
// A name longer than the allowed maximum
#define URI_NAME_TOO_LONG                                                                                              \
    URI_PREFIX                                                                                                         \
    "Cl4KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEkBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5emFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6YWJjZGVm" \
    "Z2hpamtsIAEoATACEAE%3D"

// Check a url-encoded string field decodes to the expected value
static bool check_str(const char* field, const size_t field_len, const char* expected)
{
    char decoded[OTP_MAX_LABEL_LEN];

    if (!field || !field_len) {
        FAIL();
    }
    if (!urldecode(field, field_len, decoded, sizeof(decoded))) {
        FAIL();
    }
    if (strcmp(decoded, expected)) {
        FAIL();
    }
    return true;
}

// Check the code for the passed HOTP counter or TOTP timestamp
static bool check_code(otpauth_ctx_t* otp_ctx, const int64_t value, const char* expected_code)
{
    char token[OTP_MAX_TOKEN_LEN];

    otp_set_explicit_value(otp_ctx, value);
    if (!otp_get_auth_code(otp_ctx, token, sizeof(token))) {
        FAIL();
    }
    if (strcmp(token, expected_code)) {
        FAIL();
    }
    return true;
}

// Parse a migrate uri and log if it is rejected
static bool parse_uri(const char* uri, otpauth_migrate_ctx_t* ctx)
{
    if (!otp_migrate_uri_to_ctx(uri, strlen(uri), OTP_MAX_MIGRATE_RECORDS, ctx)) {
        FAIL();
    }
    return true;
}

// Count the decodable uris in a parsed migrate context
static size_t num_decoded_uris(const otpauth_migrate_ctx_t* ctx)
{
    size_t num_uris = 0;
    for (size_t i = 0; i < ctx->uris_out_len; ++i) {
        num_uris += ctx->uris_out[i] ? 1 : 0;
    }
    return num_uris;
}

// Return whether the uri yields records which are all valid
static bool records_ok(const char* uri, size_t* num_records)
{
    otpauth_migrate_ctx_t ctx;
    if (!parse_uri(uri, &ctx)) {
        FAIL();
    }

    *num_records = 0;
    for (size_t i = 0; i < ctx.uris_out_len; ++i) {
        if (ctx.uris_out[i]) {
            otpauth_ctx_t otp_ctx = { .name = "otp" };
            char token[OTP_MAX_TOKEN_LEN];
            ++*num_records;
            if (!otp_uri_to_ctx(ctx.uris_out[i], strlen(ctx.uris_out[i]), &otp_ctx)
                || !otp_get_auth_code(&otp_ctx, token, sizeof(token))) {
                FAIL();
            }
        }
    }
    otp_migrate_uri_to_ctx_free(&ctx);
    return true;
}

typedef struct {
    const char* what; // Reject reason
    const char* uri; // Migrate uri
} uri_case_t;

// Every uri in the passed table must be rejected
static bool reject_uris(const uri_case_t* cases, const size_t num_cases)
{
    size_t num_records = 0;
    for (size_t i = 0; i < num_cases; ++i) {
        if (records_ok(cases[i].uri, &num_records)) {
            FAIL();
        }
    }
    return true;
}

typedef struct {
    int64_t value; // HOTP counter or TOTP timestamp
    const char* expected_code; // Resulting code
} otp_code_t;

// A single-record case: the migration uri, and what the 'otpauth://' uri it decodes to must
// be. 'counter' is the expected HOTP counter, and is ignored for TOTP records (which are
// instead checked to have the default period).
typedef struct {
    const char* what;
    const char* migrate_uri;
    int otp_type; // zero means the default (TOTP)
    int md_type; // zero means the default (SHA1)
    int8_t digits; // zero means the default (6)
    uint64_t counter;
    const char* expected_label;
    const char* expected_issuer; // only checked when non-empty
    const otp_code_t* codes;
    size_t num_codes;
} record_case_t;

static bool check_record_case(const record_case_t* test)
{
    otpauth_migrate_ctx_t ctx;
    otpauth_ctx_t otp_ctx = { .name = "otp" };

    const int otp_type = test->otp_type ? test->otp_type : OTPTYPE_TOTP;
    const bool is_hotp = otp_type == OTPTYPE_HOTP;

    // Parse the migrate uri and check it decodes to a single 'otpauth://' uri
    if (!parse_uri(test->migrate_uri, &ctx)) {
        FAIL();
    }
    if (num_decoded_uris(&ctx) != 1) {
        FAIL();
    }

    if (!otp_uri_to_ctx(ctx.uris_out[0], strlen(ctx.uris_out[0]), &otp_ctx)) {
        FAIL();
    }
    if (otp_ctx.otp_type != otp_type || otp_ctx.digits != (test->digits ? test->digits : 6)
        || otp_ctx.md_type != (test->md_type ? test->md_type : MDTYPE_SHA1)
        || (is_hotp ? otp_ctx.counter != test->counter : otp_ctx.period != 30)) {
        FAIL();
    }
    if (!check_str(otp_ctx.label, otp_ctx.label_len, test->expected_label)
        || (test->expected_issuer && *test->expected_issuer
            && !check_str(otp_ctx.issuer, otp_ctx.issuer_len, test->expected_issuer))) {
        FAIL();
    }
    for (size_t i = 0; i < test->num_codes; ++i) {
        if (!check_code(&otp_ctx, test->codes[i].value, test->codes[i].expected_code)) {
            FAIL();
        }
    }

    otp_migrate_uri_to_ctx_free(&ctx);
    return true;
}

static bool test_records(void)
{
    // rfc6238 test vectors
    const otp_code_t totp_codes[] = { { 59, "287082" }, { 1111111109, "081804" }, { 20000000000, "353130" } };
    const otp_code_t hotp0_codes[] = { { 0, "755224" } };
    const otp_code_t hotp5_codes[] = { { 5, "254676" } };
    const otp_code_t sha256_codes[] = { { 59, "46119246" } };
    const otp_code_t sha512_codes[] = { { 59, "90693936" } };

    const record_case_t cases[] = {
        { .what = "totp with name and issuer",
            .migrate_uri = URI_PREFIX "CjkKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhJqb2huLmRvZUBlbWFpbC5jb20aB0FDTUUgQ28gASgBMAI"
                                      "QAQ%3D%3D",
            .expected_label = "ACME Co:john.doe@email.com",
            .expected_issuer = "ACME Co",
            .codes = totp_codes,
            .num_codes = ARRAY_LEN(totp_codes) },

        // label construction - 'issuer:name', 'issuer:', 'name', and the placeholder when
        // the record has neither
        { .what = "issuer and name",
            .migrate_uri = URI_PREFIX "Cj0KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhJqYW5lLmRvZUBlbWFpbC5jb20aC0V4YW1wbGUgSW5jIAE"
                                      "oATACEAE%3D",
            .expected_label = "Example Inc:jane.doe@email.com",
            .expected_issuer = "Example Inc" },
        { .what = "issuer prefixed name",
            .migrate_uri = URI_PREFIX "CkEKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhpBQ01FIENvOmphbmUuZG9lQGVtYWls"
                                      "LmNvbRoHQUNNRSBDbyABKAEwAhAB",
            .expected_label = "ACME Co:jane.doe@email.com",
            .expected_issuer = "ACME Co" },
        { .what = "issuer only",
            .migrate_uri = URI_PREFIX "CikKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwGgtFeGFtcGxlIEluYyABKAEwAhAB",
            .expected_label = "Example Inc:",
            .expected_issuer = "Example Inc" },
        { .what = "name only",
            .migrate_uri = URI_PREFIX "CjAKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhJqYW5lLmRvZUBlbWFpbC5jb20gASgBMAIQAQ%3D%3D",
            .expected_label = "jane.doe@email.com" },
        { .what = "neither (placeholder)", .migrate_uri = URI_DEFAULT_RECORD, .expected_label = "otp" },
        { .what = "neither (empty fields)",
            .migrate_uri = URI_PREFIX "CiAKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgAaACABKAEwAhAB",
            .expected_label = "otp" },

        // HOTP records must always generate a counter parameter, including zero
        { .what = "hotp counter 0",
            .migrate_uri = URI_PREFIX "Ch4KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATABOAAQAQ%3D%3D",
            .otp_type = OTPTYPE_HOTP,
            .expected_label = "otp",
            .codes = hotp0_codes,
            .num_codes = ARRAY_LEN(hotp0_codes) },
        { .what = "hotp counter 5",
            .migrate_uri = URI_PREFIX "Ch4KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATABOAUQAQ%3D%3D",
            .otp_type = OTPTYPE_HOTP,
            .counter = 5,
            .expected_label = "otp",
            .codes = hotp5_codes,
            .num_codes = ARRAY_LEN(hotp5_codes) },

        // non-default algorithm and digit count
        { .what = "sha256/8-digit",
            .migrate_uri = URI_PREFIX "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAIoAjACEAE%3D",
            .md_type = MDTYPE_SHA256,
            .digits = 8,
            .expected_label = "otp",
            .codes = sha256_codes,
            .num_codes = ARRAY_LEN(sha256_codes) },
        { .what = "sha512/8-digit",
            .migrate_uri = URI_PREFIX "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAMoAjACEAE%3D",
            .md_type = MDTYPE_SHA512,
            .digits = 8,
            .expected_label = "otp",
            .codes = sha512_codes,
            .num_codes = ARRAY_LEN(sha512_codes) },
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); ++i) {
        if (!check_record_case(&cases[i])) {
            FAIL();
        }
    }
    return true;
}

static bool test_multiple_records(void)
{
    const char* const names[OTP_MAX_MIGRATE_RECORDS]
        = { "record0", "record1", "record2", "record3", "record4", "record5", "record6", "record7" };

    otpauth_migrate_ctx_t ctx;
    if (!parse_uri(URI_MULTIPLE_RECORDS, &ctx)) {
        FAIL(); // Should parse up to OTP_MAX_MIGRATE_RECORDS records
    }

    const size_t num_uris = num_decoded_uris(&ctx);
    if (num_uris != ARRAY_LEN(names)) {
        FAIL();
    }

    // Check each decoded record re-parses with the name it was encoded with
    for (size_t i = 0; i < num_uris; ++i) {
        otpauth_ctx_t otp_ctx = { .name = "otp" };
        if (!otp_uri_to_ctx(ctx.uris_out[i], strlen(ctx.uris_out[i]), &otp_ctx)
            || !check_str(otp_ctx.label, otp_ctx.label_len, names[i])) {
            FAIL();
        }
    }

    otp_migrate_uri_to_ctx_free(&ctx);
    return true;
}

static bool test_bad_uris(void)
{
    const uri_case_t raw_uris[] = {
        { "no data param", "otpauth-migration://offline" },
        { "empty data param", URI_PREFIX },
        { "not base64", URI_DATA_NOT_BASE64 },
        { "no base64 characters", URI_PREFIX "%20" },
        { "not protobuf", URI_PREFIX "%2F%2F8%3D" },
    };
    if (!reject_uris(raw_uris, ARRAY_LEN(raw_uris))) {
        FAIL();
    }

    const struct {
        const char* what;
        const char* format;
    } variants[] = {
        { "wrong schema", "otpauth://offline?data=%s" },
        { "wrong host", "otpauth-migration://online?data=%s" },
        { "port given", "otpauth-migration://offline:80?data=%s" },
        { "fragment given", URI_PREFIX "%s#frag" },
    };
    for (size_t i = 0; i < ARRAY_LEN(variants); ++i) {
        char uri[256];
        const int ret = snprintf(uri, sizeof(uri), variants[i].format, DATA_DEFAULT_RECORD);
        JADE_ASSERT(ret > 0 && ret < (int)sizeof(uri));
        const uri_case_t variant = { variants[i].what, uri };
        if (!reject_uris(&variant, 1)) {
            FAIL();
        }
    }

    // an empty payload is a valid uri with no records
    size_t num_records = 0;
    if (!records_ok(URI_NO_RECORDS, &num_records) || num_records) {
        FAIL();
    }
    return true;
}

static bool test_bad_records(void)
{
    // Bad records inside a uri
    const uri_case_t bad_records[] = {
        // secrets and names longer than the decoder's buffers
        { "secret too long", URI_PREFIX "CikKIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACABKAEwAhAB" },
        { "name too long", URI_NAME_TOO_LONG },
        // unsupported enum values
        { "unsupported algorithm", URI_PREFIX "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAAoATACEAE%3D" },
        { "unsupported algorithm md5", URI_PREFIX "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAQoATACEAE%3D" },
        { "unsupported digits", URI_PREFIX "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoADACEAE%3D" },
        { "unsupported type", URI_PREFIX "ChwKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATAAEAE%3D" },
        // invalid field values
        { "negative counter",
            URI_PREFIX "CicKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwIAEoATABOP%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQAQ%3D%3D" },
        { "secret absent", URI_PREFIX "CgYgASgBMAIQAQ%3D%3D" },
        { "secret empty", URI_PREFIX "CggKACABKAEwAhAB" },
        // more records than the maximum supported
        { "too many records", URI_TOO_MANY_RECORDS },
    };

    if (!reject_uris(bad_records, ARRAY_LEN(bad_records))) {
        FAIL();
    }
    return true;
}

static bool test_register_otp_migrate_string(jade_process_t* process)
{
    // first we need a wallet
    if (!selfcheck_set_test_mnemonic(process, true, true)) {
        FAIL();
    }

    const struct {
        const char* what;
        const char* uri;
        const char* expected_errmsg;
    } cases[] = {
        { "uri which does not parse", URI_DATA_NOT_BASE64, "Failed to parse otp migrate record" },
        { "uri with no records", URI_NO_RECORDS, "No otp records found in migrate uri" },
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); ++i) {
        const char* errmsg = NULL;
        const int errcode = register_otp_migrate_string(cases[i].uri, strlen(cases[i].uri), &errmsg);
        if (!errcode || !errmsg || strcmp(errmsg, cases[i].expected_errmsg)) {
            FAIL();
        }
    }
    return true;
}

bool debug_selfcheck(jade_process_t* process)
{
    if (!test_records()) {
        FAIL();
    }

    if (!test_multiple_records()) {
        FAIL();
    }

    if (!test_bad_uris() || !test_bad_records()) {
        FAIL();
    }

    if (!test_register_otp_migrate_string(process)) {
        FAIL();
    }

    return true;
}
