#ifndef AMALGAMATED_BUILD
#include "otpauth.h"
#include "aes.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "sensitive.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/urldecode.h"
#include "utils/util.h"

#include <google-otpauth-migration.pb.h>
#include <http_parser.h>
#include <mbedtls/md.h>
#include <pb_decode.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MBEDTLS_SHA512_HMAC_LEN 64
#define SECRET_BUFSIZE 256

// Max byte length of a protobuf string field (name/issuer) in an OTP migration payload
#define OTP_MIGRATE_PB_FIELD_LEN 64

static const uint8_t OTP_HMAC_KEY[] = { 'O', 'T', 'P', 's', 'e', 'e', 'd' };

// Check current timestamp is after Jan 01 2020 (just a sanity check that we have set the clock)
#define MIN_ALLOWED_CURRENT_TIMESTAMP 1577836800

#define OTP_CHECK_BOOL_RETURN(expr)                                                                                    \
    do {                                                                                                               \
        const bool ret = (expr);                                                                                       \
        if (!ret) {                                                                                                    \
            JADE_LOGE("OTP failure");                                                                                  \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Check otpauth_ctx_t object is valid
bool otp_is_valid(const otpauth_ctx_t* otp_ctx)
{
    OTP_CHECK_BOOL_RETURN(otp_ctx);

    // Mandatory fields
    OTP_CHECK_BOOL_RETURN(otp_ctx->name);
    OTP_CHECK_BOOL_RETURN(otp_ctx->type && otp_ctx->type_len);
    OTP_CHECK_BOOL_RETURN(otp_ctx->secret && otp_ctx->secret_len);
    OTP_CHECK_BOOL_RETURN(otp_ctx->otp_type == OTPTYPE_HOTP || otp_ctx->otp_type == OTPTYPE_TOTP);
    OTP_CHECK_BOOL_RETURN(otp_ctx->otp_type != OTPTYPE_TOTP || otp_ctx->period);
    OTP_CHECK_BOOL_RETURN(otp_ctx->digits == 6 || otp_ctx->digits == 8);
    OTP_CHECK_BOOL_RETURN(otp_ctx->md_type);

    // Optional fields
    OTP_CHECK_BOOL_RETURN(!otp_ctx->label_len || otp_ctx->label);
    OTP_CHECK_BOOL_RETURN(!otp_ctx->issuer_len || otp_ctx->issuer);

    return true;
}

// Note: 'qry_ptr' does not need to be nul-terminated
// 'key' *is* expected to be nul-terminated.
static bool get_query_argument(
    const char* const qry_ptr, const size_t qry_len, const char* key, const char** val, size_t* val_len)
{
    JADE_ASSERT(qry_ptr);
    JADE_ASSERT(key);
    JADE_INIT_OUT_PPTR(val);
    JADE_INIT_OUT_SIZE(val_len);

    const size_t key_len = strlen(key);
    const char* const p_end = qry_ptr + qry_len;
    const char* ptr = qry_ptr;

    while (ptr < p_end) {
        const char* p_equals = memchr(ptr, '=', p_end - ptr);
        if (!p_equals) {
            // Exhausted string looking for '=' - malformed query string
            JADE_LOGE("Malformed query string: %.*s", qry_len, qry_ptr);
            return false;
        }

        const size_t len = p_equals - ptr;
        const bool match = ((len == key_len) && !strncasecmp(ptr, key, len));

        // Move ptr to end of value/start of next argument
        ptr = memchr(p_equals, '&', p_end - p_equals);
        if (!ptr) {
            // Final value in query string, no following '&'
            ptr = p_end;
        }

        if (match) {
            // Found!  Copy fields and return true
            *val = p_equals + 1;
            *val_len = ptr - *val;
            return true;
        }

        // Bump past the '&'
        ++ptr;
    }

    // Not found
    return false;
}

bool otp_uri_to_ctx(const char* uri, size_t uri_len, otpauth_ctx_t* otp_ctx)
{
    JADE_ASSERT(uri);
    JADE_ASSERT(otp_ctx);

    struct http_parser_url u;
    http_parser_url_init(&u);
    OTP_CHECK_BOOL_RETURN(http_parser_parse_url(uri, uri_len, 0, &u) == 0);

    if (u.field_data[UF_SCHEMA].len != 7
        || strncmp(OTP_SCHEMA, uri + u.field_data[UF_SCHEMA].off, u.field_data[UF_SCHEMA].len)) {
        JADE_LOGE("otp uri missing expected %s schema", OTP_SCHEMA_FULL);
        return false;
    }

    OTP_CHECK_BOOL_RETURN(u.field_set & (1 << UF_SCHEMA));
    OTP_CHECK_BOOL_RETURN(u.field_set & (1 << UF_HOST));
    OTP_CHECK_BOOL_RETURN(u.field_set & (1 << UF_QUERY));
    OTP_CHECK_BOOL_RETURN(!(u.field_set & (1 << UF_PORT)));
    OTP_CHECK_BOOL_RETURN(!(u.field_set & (1 << UF_FRAGMENT)));

    // HOTP/TOTP type is in the 'host' position
    otp_ctx->type = uri + u.field_data[UF_HOST].off;
    otp_ctx->type_len = u.field_data[UF_HOST].len;

    // 'label' is in the 'path' position, but we need to skip the leading '/'
    otp_ctx->label = uri + u.field_data[UF_PATH].off + 1;
    otp_ctx->label_len = u.field_data[UF_PATH].len - 1;

    // Other fields are in the query/parameters string
    const char* query = uri + u.field_data[UF_QUERY].off;
    const size_t query_len = u.field_data[UF_QUERY].len;

    // 'secret' is mandatory
    OTP_CHECK_BOOL_RETURN(get_query_argument(query, query_len, "secret", &otp_ctx->secret, &otp_ctx->secret_len));
    OTP_CHECK_BOOL_RETURN(otp_ctx->secret && otp_ctx->secret_len);

    // 'issuer' is not (?)
    get_query_argument(query, query_len, "issuer", &otp_ctx->issuer, &otp_ctx->issuer_len);

    const char* tmp = NULL;
    size_t tmp_len = 0;

    // Digits defaults to 6 but can be specified as 8
    get_query_argument(query, query_len, "digits", &tmp, &tmp_len);
    OTP_CHECK_BOOL_RETURN(!tmp || tmp_len == 1);
    if (!tmp) {
        otp_ctx->digits = 6;
    } else {
        otp_ctx->digits = *tmp - '0';
        OTP_CHECK_BOOL_RETURN(otp_ctx->digits == 6 || otp_ctx->digits == 8);
    }

    // 'algorithm' defaults to SHA1, but can be specified as SHA256 or SHA512
    if (!get_query_argument(query, query_len, "algorithm", &tmp, &tmp_len)
        || (tmp_len == 4 && !strncmp("SHA1", tmp, tmp_len))) {
        otp_ctx->md_type = MDTYPE_SHA1;
    } else if (tmp_len == 6 && !strncmp("SHA256", tmp, tmp_len)) {
        otp_ctx->md_type = MDTYPE_SHA256;
    } else if (tmp_len == 6 && !strncmp("SHA512", tmp, tmp_len)) {
        otp_ctx->md_type = MDTYPE_SHA512;
    } else {
        JADE_LOGE("Unknown algorithm %.*s", tmp_len, tmp);
        return false;
    }

    // Get counter(hotp) or period(totp)
    if (otp_ctx->type_len == 4 && !strncmp("hotp", otp_ctx->type, otp_ctx->type_len)) {
        otp_ctx->otp_type = OTPTYPE_HOTP;

        // 'counter' is mandatory for hotp
        OTP_CHECK_BOOL_RETURN(get_query_argument(query, query_len, "counter", &tmp, &tmp_len));
        OTP_CHECK_BOOL_RETURN(tmp && tmp_len > 0 && tmp_len <= 20);

        // Needs copying to nul-terminated buffer before converting
        char buf[20];
        memcpy(buf, tmp, tmp_len);
        buf[tmp_len] = '\0';
        otp_ctx->counter = strtoull(buf, NULL, 10);
    } else if (otp_ctx->type_len == 4 && strncmp("totp", otp_ctx->type, otp_ctx->type_len) == 0) {
        otp_ctx->otp_type = OTPTYPE_TOTP;

        // Period can be specified, but defaults to 30s
        get_query_argument(query, query_len, "period", &tmp, &tmp_len);
        if (!tmp) {
            otp_ctx->period = 30;
        } else {
            OTP_CHECK_BOOL_RETURN(tmp_len > 0 && tmp_len <= 3);

            // Needs copying to nul-terminated buffer before converting
            char buf[4];
            memcpy(buf, tmp, tmp_len);
            buf[tmp_len] = '\0';
            otp_ctx->period = strtoul(buf, NULL, 10);
        }
    } else {
        JADE_LOGE("Unknown OTP type: %.*s", otp_ctx->type_len, otp_ctx->type);
        return false;
    }

    return otp_is_valid(otp_ctx);
}

#define OTP_MIGRATE_SCHEMA_OFFSET 8
#define OTP_MIGRATE_REQ_FIELDS ((1 << UF_SCHEMA) | (1 << UF_HOST) | (1 << UF_QUERY))
#define OTP_MIGRATE_INVALID_FIELDS ((1 << UF_PORT) | (1 << UF_FRAGMENT))

// NOTE: 'data' ownership is assigned to the caller who must free after use
static bool otp_migrate_url_to_data(const char* uri, size_t uri_len, uint8_t** data, size_t* data_len)
{
    JADE_ASSERT(uri);
    JADE_INIT_OUT_PPTR(data);
    JADE_INIT_OUT_SIZE(data_len);

    // http_parser_parse_url() does not like non-alphabetic chars in the schema
    if (strncmp(uri, OTP_MIGRATE_SCHEMA, sizeof(OTP_MIGRATE_SCHEMA) - 1) == 0) {
        // change schema to remove '-' char
        uri += OTP_MIGRATE_SCHEMA_OFFSET;
        uri_len -= OTP_MIGRATE_SCHEMA_OFFSET;
    }

    struct http_parser_url u;
    http_parser_url_init(&u);
    OTP_CHECK_BOOL_RETURN(http_parser_parse_url(uri, uri_len, 0, &u) == 0);

    if (u.field_data[UF_SCHEMA].len != 9
        || strncmp(OTP_MIGRATE_SCHEMA + OTP_MIGRATE_SCHEMA_OFFSET, uri + u.field_data[UF_SCHEMA].off,
            u.field_data[UF_SCHEMA].len)) {
        JADE_LOGE("otp migrate uri missing expected " OTP_MIGRATE_SCHEMA_FULL " schema");
        return false;
    }

    OTP_CHECK_BOOL_RETURN((u.field_set & OTP_MIGRATE_REQ_FIELDS) == OTP_MIGRATE_REQ_FIELDS);
    OTP_CHECK_BOOL_RETURN(!(u.field_set & OTP_MIGRATE_INVALID_FIELDS));

    // 'offline' string is in the 'host' position
    if (u.field_data[UF_HOST].len != 7
        || strncmp(OTP_MIGRATE_HOST, uri + u.field_data[UF_HOST].off, u.field_data[UF_HOST].len)) {
        JADE_LOGE("otp migrate uri missing expected " OTP_MIGRATE_HOST " host");
        return false;
    }

    // Remaining field is in the query/parameters string
    const char* query = uri + u.field_data[UF_QUERY].off;
    const size_t query_len = u.field_data[UF_QUERY].len;

    // 'data' is mandatory
    const char* data_param = NULL;
    size_t data_param_len = 0;
    OTP_CHECK_BOOL_RETURN(get_query_argument(query, query_len, "data", &data_param, &data_param_len));
    OTP_CHECK_BOOL_RETURN(data_param && data_param_len);

    // urldecode the data query parameter
    char* data_b64 = JADE_MALLOC(data_param_len + 1);
    SENSITIVE_PUSH(data_b64, data_param_len + 1);
    if (!urldecode(data_param, data_param_len, data_b64, data_param_len + 1)) {
        JADE_LOGE("Failed to urldecode otp migrate data");
        SENSITIVE_POP(data_b64);
        free(data_b64);
        return false;
    }
    size_t data_b64_len = strlen(data_b64);

    // convert from base64
    size_t data_max_len;
    JADE_WALLY_VERIFY(wally_base64_get_maximum_length(data_b64, 0, &data_max_len));
    *data = JADE_MALLOC(data_max_len);
    JADE_WALLY_VERIFY(wally_base64_n_to_bytes(data_b64, data_b64_len, 0, *data, data_max_len, data_len));
    SENSITIVE_POP(data_b64);
    free(data_b64);

    return true;
}

static bool otp_uri_insert(char* uri, const char* prefix, const char* value)
{
    const size_t prefix_len = strlen(prefix);
    const size_t value_len = strlen(value);
    const size_t uri_len = strlen(uri);
    if (uri_len + value_len >= OTP_MAX_URI_LEN) {
        return false;
    }
    memmove(uri + prefix_len + value_len, uri + prefix_len, uri_len - prefix_len + 1);
    memcpy(uri + prefix_len, value, value_len);
    return true;
}

static size_t pb_read_stream(pb_istream_t* stream, const char* name, uint8_t* buf, size_t buf_len)
{
    const size_t num_bytes = stream->bytes_left;
    if (num_bytes > buf_len) {
        JADE_LOGE("%s buffer too small", name);
        return 0;
    }
    if (!pb_read(stream, buf, num_bytes)) {
        JADE_LOGE("%s read failed", name);
        return 0;
    }
    return num_bytes;
}

static bool append_uri_param(char* uri, const char* key, const char* value, bool first)
{
    const size_t uri_len = strlen(uri);
    int n = snprintf(uri + uri_len, OTP_MAX_URI_LEN - uri_len, "%c%s=%s", first ? '?' : '&', key, value);
    if (n < 0 || n >= OTP_MAX_URI_LEN - uri_len) {
        return false;
    }
    return true;
}

static bool decode_secret_fn(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    uint8_t buf[32];
    SENSITIVE_PUSH(buf, sizeof(buf));
    const size_t buf_len = pb_read_stream(stream, "secret", buf, sizeof(buf));
    if (!buf_len) {
        SENSITIVE_POP(buf);
        return false;
    }

    // convert to base32
    char base32[sizeof(buf) * 2];
    SENSITIVE_PUSH(base32, sizeof(base32));
    const bool use_padding = false; // padding not used for uris because '=' char is not url-safe
    bool ret = bin_to_base32(buf, buf_len, base32, sizeof(base32), use_padding);
    if (ret) {
        // write to output arg
        char* opt_uri = (char*)(*arg);
        ret = append_uri_param(opt_uri, "secret", base32, true);
    }
    SENSITIVE_POP(base32);
    SENSITIVE_POP(buf);
    return ret;
}

typedef struct {
    char* uri_out;
    // Buffers to hold url-encoded name and issuer, populated during pb_decode.
    // URI construction is deferred to after pb_decode to avoid field-ordering issues.
    // https://protobuf.dev/programming-guides/encoding/#order
    char name_encoded[OTP_MIGRATE_PB_FIELD_LEN * 3 + 1];
    bool has_name;
    bool name_has_colon;
    char issuer_encoded[OTP_MIGRATE_PB_FIELD_LEN * 3 + 1];
    bool has_issuer;
} otp_migrate_decode_str_ctx_t;

static bool decode_name_fn(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    uint8_t buf[OTP_MIGRATE_PB_FIELD_LEN];
    const size_t buf_len = pb_read_stream(stream, "name", buf, sizeof(buf) - 1);
    if (!buf_len) {
        return false;
    }
    buf[buf_len] = '\0';

    JADE_LOGI("Decoded name: %s", buf);

    otp_migrate_decode_str_ctx_t* str_ctx = (otp_migrate_decode_str_ctx_t*)(*arg);

    // check if name contains a ':' character, in which case we will not prefix the name
    // with the issuer later on
    str_ctx->name_has_colon = memchr(buf, ':', buf_len) != NULL;

    // uriencode the name value and store for post-decode URI construction
    if (!urlencode((char*)buf, buf_len, str_ctx->name_encoded, sizeof(str_ctx->name_encoded))) {
        return false;
    }
    str_ctx->has_name = true;
    return true;
}

static bool decode_issuer_fn(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    uint8_t buf[OTP_MIGRATE_PB_FIELD_LEN];
    const size_t buf_len = pb_read_stream(stream, "issuer", buf, sizeof(buf) - 1);
    if (!buf_len) {
        return false;
    }
    buf[buf_len] = '\0';

    JADE_LOGI("Decoded issuer: %s", buf);

    otp_migrate_decode_str_ctx_t* str_ctx = (otp_migrate_decode_str_ctx_t*)(*arg);

    // uriencode the issuer value and store for post-decode URI construction
    if (!urlencode((char*)buf, buf_len, str_ctx->issuer_encoded, sizeof(str_ctx->issuer_encoded))) {
        return false;
    }
    str_ctx->has_issuer = true;
    return true;
}

static bool decode_otp_parameters_fn(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    otpauth_migrate_ctx_t* ctx = (otpauth_migrate_ctx_t*)(*arg);

    // find first empty slot in output array
    size_t i;
    for (i = 0; i < ctx->uris_out_len; ++i) {
        if (ctx->uris_out[i] == NULL) {
            break;
        }
    }
    if (i == ctx->uris_out_len) {
        JADE_LOGE("Too many OTP records in migration data, max supported is %zu", ctx->uris_out_len);
        return false;
    }

    // allocate output URI buffer
    ctx->uris_out[i] = JADE_MALLOC(OTP_MAX_URI_LEN);
    char* uri_out = ctx->uris_out[i];

    // start with schema
    const int ret = snprintf(uri_out, OTP_MAX_URI_LEN, OTP_SCHEMA_FULL);
    JADE_ASSERT(ret > 0 && ret < OTP_MAX_URI_LEN);

    // decode the message into the URI
    MigrationPayload_OtpParameters message = MigrationPayload_OtpParameters_init_zero;
    message.secret.funcs.decode = decode_secret_fn;
    message.secret.arg = uri_out;
    otp_migrate_decode_str_ctx_t str_ctx = { .uri_out = uri_out,
        .name_encoded = { 0 },
        .has_name = false,
        .name_has_colon = false,
        .issuer_encoded = { 0 },
        .has_issuer = false };
    message.name.funcs.decode = decode_name_fn;
    message.name.arg = &str_ctx;
    message.issuer.funcs.decode = decode_issuer_fn;
    message.issuer.arg = &str_ctx;
    if (!pb_decode(stream, MigrationPayload_OtpParameters_fields, &message)) {
        JADE_LOGE("otp migrate data decode failed");
        return false;
    }

    // Insert name and issuer into URI now that all fields are decoded, avoiding
    // field-ordering issues that might arise if done inside the individual callbacks.
    if (str_ctx.has_name) {
        if (!otp_uri_insert(uri_out, OTP_SCHEMA_FULL, str_ctx.name_encoded)) {
            return false;
        }
    }
    if (str_ctx.has_issuer) {
        if (!str_ctx.name_has_colon) {
            // prefix label with "issuer:" to form "otpauth://<type>/<issuer>:<name>?..."
            if (!otp_uri_insert(uri_out, OTP_SCHEMA_FULL, ":")) {
                return false;
            }
            if (!otp_uri_insert(uri_out, OTP_SCHEMA_FULL, str_ctx.issuer_encoded)) {
                return false;
            }
        }
        if (!append_uri_param(uri_out, "issuer", str_ctx.issuer_encoded, false)) {
            return false;
        }
    }

    // insert OTP type
    switch (message.type) {
    case MigrationPayload_OtpType_OTP_TYPE_HOTP:
        if (!otp_uri_insert(uri_out, OTP_SCHEMA_FULL, "hotp/")) {
            return false;
        }
        break;
    case MigrationPayload_OtpType_OTP_TYPE_TOTP:
        if (!otp_uri_insert(uri_out, OTP_SCHEMA_FULL, "totp/")) {
            return false;
        }
        break;
    default:
        JADE_LOGE("Unsupported OTP type: %d", (int)message.type);
        return false;
    }

    // add algorithm if not default (SHA1)
    if (message.algorithm != MigrationPayload_Algorithm_ALGORITHM_SHA1) {
        const char* algo = NULL;
        switch (message.algorithm) {
        case MigrationPayload_Algorithm_ALGORITHM_SHA256:
            algo = "SHA256";
            break;
        case MigrationPayload_Algorithm_ALGORITHM_SHA512:
            algo = "SHA512";
            break;
        case MigrationPayload_Algorithm_ALGORITHM_MD5:
            algo = "MD5";
            break;
        default:
            JADE_LOGE("Unsupported algorithm: %d", (int)message.algorithm);
            return false;
        }
        if (!append_uri_param(uri_out, "algorithm", algo, false)) {
            return false;
        }
    }

    // add digits if not default (6)
    if (message.digits != MigrationPayload_DigitCount_DIGIT_COUNT_SIX) {
        switch (message.digits) {
        case MigrationPayload_DigitCount_DIGIT_COUNT_EIGHT:
            if (!append_uri_param(uri_out, "digits", "8", false)) {
                return false;
            }
            break;
        default:
            JADE_LOGE("Unsupported digit count: %d", (int)message.digits);
            return false;
        }
    }

    // add counter if HOTP and counter > 0
    if (message.type == MigrationPayload_OtpType_OTP_TYPE_HOTP && message.counter > 0) {
        char counter_str[21]; // Big enough to hold 64-bit integer
        const int ret = snprintf(counter_str, sizeof(counter_str), "%" PRId64, message.counter);
        JADE_ASSERT(ret > 0 && ret < sizeof(counter_str));
        if (!append_uri_param(uri_out, "counter", counter_str, false)) {
            return false;
        }
    }
    return true;
}

void otp_migrate_uri_to_ctx_free(otpauth_migrate_ctx_t* ctx)
{
    JADE_ASSERT(ctx && ctx->uris_out);
    for (size_t i = 0; i < ctx->uris_out_len; ++i) {
        if (ctx->uris_out[i]) {
            JADE_WALLY_VERIFY(wally_free_string(ctx->uris_out[i]));
            ctx->uris_out[i] = NULL;
        }
    }
    free(ctx->uris_out);
    ctx->uris_out = NULL;
    ctx->uris_out_len = 0;
}

bool otp_migrate_uri_to_ctx(const char* uri, const size_t uri_len, const size_t max_uris, otpauth_migrate_ctx_t* ctx)
{
    JADE_ASSERT(uri && uri_len);
    JADE_ASSERT(max_uris);
    JADE_ASSERT(ctx);

    // Initialize the context
    ctx->uris_out = JADE_CALLOC(max_uris, sizeof(char*));
    ctx->uris_out_len = max_uris;

    // convert the otpauth-migration data param (base64) into binary data
    uint8_t* data;
    size_t data_len;
    OTP_CHECK_BOOL_RETURN(otp_migrate_url_to_data(uri, uri_len, &data, &data_len));
    SENSITIVE_PUSH(data, data_len);

    bool result = false;

    // protobuf decode
    MigrationPayload message = MigrationPayload_init_zero;
    message.otp_parameters.funcs.decode = decode_otp_parameters_fn;
    message.otp_parameters.arg = ctx;
    pb_istream_t stream = pb_istream_from_buffer(data, data_len);
    if (!pb_decode(&stream, MigrationPayload_fields, &message)) {
        JADE_LOGE("otp migrate data decode failed");
        goto cleanup;
    }

    result = true;

cleanup:
    SENSITIVE_POP(data);
    free(data);

    return result;
}

void otp_set_explicit_value(otpauth_ctx_t* otp_ctx, const int64_t value)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));

    if (otp_ctx->otp_type == OTPTYPE_TOTP) {
        // Convert passed timestamp to counter value
        otp_ctx->counter = value / otp_ctx->period;
    } else {
        otp_ctx->counter = value;
    }
}

otp_err_t otp_set_default_value(otpauth_ctx_t* otp_ctx, uint64_t* value_out)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));

    uint64_t value = 0;
    if (otp_ctx->otp_type == OTPTYPE_TOTP) {
        // TOTP uses the current timestamp
        value = time(NULL);
        if (value < MIN_ALLOWED_CURRENT_TIMESTAMP) {
            JADE_LOGE("Using TOTP without time set!");
            return OTP_ERR_TOTP_TIME;
        }
    } else {
        // HOTP uses an incrementing counter held in storage
        value = storage_get_otp_hotp_counter(otp_ctx->name);
        if (!storage_set_otp_hotp_counter(otp_ctx->name, value + 1)) {
            JADE_LOGE("Failed to increment HOTP counter!");
            return OTP_ERR_HOTP_COUNTER;
        }
    }

    // Set current value
    otp_set_explicit_value(otp_ctx, value);
    if (value_out) {
        *value_out = value;
    }
    return OTP_ERR_OK;
}

static inline mbedtls_md_type_t get_md_type(const otpauth_ctx_t* otp_ctx)
{
    JADE_ASSERT(otp_ctx);

    switch (otp_ctx->md_type) {
    case MDTYPE_SHA1:
        return MBEDTLS_MD_SHA1;
    case MDTYPE_SHA256:
        return MBEDTLS_MD_SHA256;
    case MDTYPE_SHA512:
        return MBEDTLS_MD_SHA512;
    default:
        return MBEDTLS_MD_NONE;
    }
}

static void pad_secret(uint8_t* secret, size_t* secret_len, const size_t min_size)
{
    JADE_ASSERT(secret);
    JADE_ASSERT(secret_len);
    JADE_ASSERT(*secret_len);
    JADE_ASSERT(min_size);

    const size_t actual_len = *secret_len;
    while (*secret_len < min_size) {
        const size_t reminder = min_size - *secret_len;
        const size_t max = min_u16(reminder, actual_len);

        memcpy(secret + *secret_len, secret, max);
        *secret_len += max;
    }
}

/*
 * NOTE:
 * There is some uncertainty around secrets padding when shorter than the hash size.
 * rfc6238 test vectors appear to suggest the secrets should be lengthened by repetition to the
 * length of the hash, although gauth-like implementations do not appear to do this - rather
 * they just use the short secret as is.
 * To maintain maximum compatibility we do not lengthen the secret for SHA1 *only*, and we do
 * lengthen short secrets for other hash digest algorithms.
 * This provides compatability with gauth-like services, and should also remain compatible with
 * HOTP/SHA1 which does not extend the secrets.
 */
static bool prepare_md_ctx(const otpauth_ctx_t* otp_ctx, mbedtls_md_context_t* md_ctx)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(md_ctx);

    mbedtls_md_init(md_ctx);
    mbedtls_md_type_t md_type = get_md_type(otp_ctx);
    OTP_CHECK_BOOL_RETURN(mbedtls_md_setup(md_ctx, mbedtls_md_info_from_type(md_type), 1) == 0);

    bool ret = false;
    uint8_t secret_bin[SECRET_BUFSIZE];
    SENSITIVE_PUSH(secret_bin, sizeof(secret_bin));
    size_t secret_bin_len = base32_to_bin(otp_ctx->secret, otp_ctx->secret_len, secret_bin, sizeof(secret_bin));
    if (!secret_bin_len) {
        JADE_LOGE("Bad Base32 secret decode");
        goto done;
    }

    // Do not lengthen/pad the secret for SHA1 *only* - for gauth compatibility.
    // Extend secret (by repetition) to at least the size of the hash in all other cases,
    // as appears necessary to match the test vectors in rfc6238.
    // (See also https://github.com/Daegalus/dart-otp#global-settings)
    if (md_type != MBEDTLS_MD_SHA1) {
        // FIXME: use getters instead of MBEDTLS_PRIVATE MACRO
        const size_t hmac_size = mbedtls_md_get_size(md_ctx->MBEDTLS_PRIVATE(md_info));
        pad_secret(secret_bin, &secret_bin_len, hmac_size);
    }
    ret = mbedtls_md_hmac_starts(md_ctx, secret_bin, secret_bin_len) == 0;

done:
    SENSITIVE_POP(secret_bin);
    return ret;
}

bool otp_get_auth_code(const otpauth_ctx_t* otp_ctx, char* token, const size_t token_len)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(token);
    JADE_ASSERT(token_len);
    JADE_ASSERT(token_len > otp_ctx->digits);

    // Calculate otp hmac of counter (be) with the secret as the key
    mbedtls_md_context_t md_ctx;
    OTP_CHECK_BOOL_RETURN(prepare_md_ctx(otp_ctx, &md_ctx));

    const size_t hmac_last_index = mbedtls_md_get_size(md_ctx.MBEDTLS_PRIVATE(md_info)) - 1;
    JADE_ASSERT(hmac_last_index < MBEDTLS_SHA512_HMAC_LEN);

    // Counter to BE bytes
    uint8_t rcnt_buf[2 * sizeof(uint32_t)];
    JADE_STATIC_ASSERT(sizeof(rcnt_buf) == sizeof(otp_ctx->counter));
    const uint8_t* const p2nd = (uint8_t*)(&otp_ctx->counter) + sizeof(uint32_t);
    uint32_to_be(*(uint32_t*)p2nd, rcnt_buf);
    uint32_to_be((uint32_t)otp_ctx->counter, rcnt_buf + sizeof(uint32_t));

    uint8_t hmac[MBEDTLS_SHA512_HMAC_LEN];
    OTP_CHECK_BOOL_RETURN(mbedtls_md_hmac_update(&md_ctx, rcnt_buf, sizeof(rcnt_buf)) == 0);
    OTP_CHECK_BOOL_RETURN(mbedtls_md_hmac_finish(&md_ctx, hmac) == 0);
    mbedtls_md_free(&md_ctx);

    // Calculate the otp code from the bytes
    const size_t offset = hmac[hmac_last_index] & 0xf;
    const int32_t full_code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16)
        | ((hmac[offset + 2] & 0xff) << 8) | ((hmac[offset + 3] & 0xff));
    const int32_t mod = otp_ctx->digits == 6 ? 1000000 : 100000000;
    const int32_t trunc_code = full_code % mod;

    // Format as a string with leading 0's
    const int ret = snprintf(token, token_len, "%0*ld", otp_ctx->digits, trunc_code);
    JADE_ASSERT(ret > 0 && ret < token_len);

    return true;
}

static bool get_otp_encryption_key(uint8_t* aeskey, const size_t aeskey_len)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aeskey_len == AES_KEY_LEN_256);
    JADE_ASSERT(keychain_get());

    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.");
        return false;
    }

    // Derive an key from the seed (use mainnet version flag as irrelevant here)
    struct ext_key key = {};
    JADE_WALLY_VERIFY(bip32_key_from_seed_custom(keychain_get()->seed, keychain_get()->seed_len, BIP32_VER_MAIN_PRIVATE,
        OTP_HMAC_KEY, sizeof(OTP_HMAC_KEY), 0, &key));

    JADE_STATIC_ASSERT(sizeof(key.priv_key) - 1 == AES_KEY_LEN_256);
    memcpy(aeskey, key.priv_key + 1, sizeof(key.priv_key) - 1);
    return true;
}

// Function to encrypt uri and store in nvs
// NOTE: otp_name must be nul-terminated, uri does not
bool otp_save_uri(const char* otp_name, const char* uri, const size_t uri_len)
{
    JADE_ASSERT(otp_name);
    JADE_ASSERT(uri);
    JADE_ASSERT(uri_len);

    bool ret = false;
    uint8_t encrypted[AES_ENCRYPTED_LEN(uri_len)];

    uint8_t aeskey[AES_KEY_LEN_256];
    SENSITIVE_PUSH(&aeskey, sizeof(aeskey));
    if (!get_otp_encryption_key(aeskey, sizeof(aeskey))) {
        JADE_LOGE("Failed to derive otp encryption key");
        goto cleanup;
    }

    if (!aes_encrypt_bytes(aeskey, sizeof(aeskey), (const uint8_t*)uri, uri_len, encrypted, sizeof(encrypted))) {
        JADE_LOGE("Failed to encrypt otp bytes");
        goto cleanup;
    }

    if (!storage_set_otp_data(otp_name, encrypted, sizeof(encrypted))) {
        JADE_LOGE("Failed to persist encrypted otp details");
        goto cleanup;
    }

    // Otherwise all good
    ret = true;

cleanup:
    SENSITIVE_POP(&aeskey);
    return ret;
}

// Function to load encrypted uri from nvs and decrypt
// NOTE: otp_name must be nul-terminated (persisted uri does not)
bool otp_load_uri(const char* otp_name, char* uri, const size_t uri_len, size_t* written)
{
    JADE_ASSERT(otp_name);
    JADE_ASSERT(uri);
    JADE_ASSERT(uri_len == OTP_MAX_URI_LEN);
    JADE_INIT_OUT_SIZE(written);

    bool ret = false;
    uint8_t aeskey[AES_KEY_LEN_256];
    SENSITIVE_PUSH(&aeskey, sizeof(aeskey));

    size_t encrypted_len = 0;
    uint8_t encrypted[AES_ENCRYPTED_LEN(OTP_MAX_URI_LEN)];
    if (!storage_get_otp_data(otp_name, encrypted, sizeof(encrypted), &encrypted_len) || !encrypted_len) {
        JADE_LOGE("Failed to load encrypted otp details");
        goto cleanup;
    }

    if (!get_otp_encryption_key(aeskey, sizeof(aeskey))) {
        JADE_LOGE("Failed to derive otp encryption key");
        goto cleanup;
    }

    if (!aes_decrypt_bytes(aeskey, sizeof(aeskey), encrypted, encrypted_len, (uint8_t*)uri, uri_len, written)) {
        JADE_LOGE("Failed to decrypt otp bytes");
        goto cleanup;
    }

    // Otherwise all good
    ret = true;

cleanup:
    SENSITIVE_POP(&aeskey);
    return ret;
}
#endif // AMALGAMATED_BUILD
