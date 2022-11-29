#include "otpauth.h"
#include "aes.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "sensitive.h"
#include "storage.h"
#include "utils/util.h"

#include <http_parser.h>
#include <mbedtls/md.h>

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MBEDTLS_SHA512_HMAC_LEN 64
#define SECRET_BUFSIZE 256

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

bool otp_set_default_value(otpauth_ctx_t* otp_ctx, uint64_t* value_out)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));

    uint64_t value = 0;
    if (otp_ctx->otp_type == OTPTYPE_TOTP) {
        // TOTP uses the current timestamp
        value = time(NULL);
        if (value < MIN_ALLOWED_CURRENT_TIMESTAMP) {
            JADE_LOGE("Using TOTP without time set!");
            return false;
        }
    } else {
        // HOTP uses an incrementing counter held in storage
        value = storage_get_otp_hotp_counter(otp_ctx->name);
        if (!storage_set_otp_hotp_counter(otp_ctx->name, value + 1)) {
            JADE_LOGE("Failed to increment HOTP counter!");
            return false;
        }
    }

    // Set current value
    otp_set_explicit_value(otp_ctx, value);
    if (value_out) {
        *value_out = value;
    }
    return true;
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

static bool base32_to_bin(
    const char* b32_str, const size_t b32_str_len, uint8_t* b32_dec, const size_t b32_dec_len, size_t* done)
{
    JADE_ASSERT(b32_str);
    JADE_ASSERT(b32_str_len);
    JADE_ASSERT(b32_dec);
    JADE_ASSERT(b32_dec_len);
    JADE_ASSERT(done);

    int tmp = 0;
    uint8_t count = 0;
    *done = 0;
    const char* b32_str_end = b32_str + b32_str_len;
    while (b32_str < b32_str_end && *b32_str) {
        char ch = *b32_str++;

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            ch = (ch & 0x1F) - 1;
        } else if (ch >= '2' && ch <= '7') {
            ch -= 24;
        } else {
            // Bad character
            return false;
        }

        tmp <<= 5;
        tmp |= ch;
        count += 5;
        if (count >= 8) {
            if (*done < b32_dec_len) {
                b32_dec[(*done)++] = tmp >> (count - 8);
                count -= 8;
            } else {
                // Destination size insufficient
                return false;
            }
        }
    }
    return true;
}

static inline uint16_t min(uint16_t a, uint16_t b) { return a < b ? a : b; }

static void pad_secret(uint8_t* secret, size_t* secret_len, const size_t min_size)
{
    JADE_ASSERT(secret);
    JADE_ASSERT(secret_len);
    JADE_ASSERT(*secret_len);
    JADE_ASSERT(min_size);

    const size_t actual_len = *secret_len;
    while (*secret_len < min_size) {
        const size_t reminder = min_size - *secret_len;
        const size_t max = min(reminder, actual_len);

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

    mbedtls_md_type_t md_type = get_md_type(otp_ctx);
    OTP_CHECK_BOOL_RETURN(mbedtls_md_setup(md_ctx, mbedtls_md_info_from_type(md_type), 1) == 0);
    const size_t hmac_size = mbedtls_md_get_size(md_ctx->md_info);

    const char* ptr = otp_ctx->secret;

    // Sanity check - can't really happen atm as entire URI length is limited
    if (otp_ctx->secret_len / 1.6 > SECRET_BUFSIZE) {
        JADE_LOGE("Bad Base32 secret decode - secret length: %.*s", otp_ctx->secret_len, otp_ctx->secret);
        return false;
    }

    size_t done = 0;
    uint8_t b32_dec[SECRET_BUFSIZE];
    const bool base32_decode_result = base32_to_bin(ptr, otp_ctx->secret_len, b32_dec, sizeof(b32_dec), &done);

    if (!base32_decode_result || !done) {
        JADE_LOGE("Bad Base32 secret decode - secret: %.*s", otp_ctx->secret_len, otp_ctx->secret);
        return false;
    }

    // Do not lengthen/pad the secret for SHA1 *only* - for gauth compatibility.
    // Extend secret (by repetition) to at least the size of the hash in all other cases,
    // as appears necessary to match the test vectors in rfc6238.
    // (See also https://github.com/Daegalus/dart-otp#global-settings)
    if (md_type != MBEDTLS_MD_SHA1) {
        pad_secret(b32_dec, &done, hmac_size);
    }

    return mbedtls_md_hmac_starts(md_ctx, b32_dec, done) == 0;
}

bool otp_get_auth_code(const otpauth_ctx_t* otp_ctx, char* token, const size_t token_len)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(token);
    JADE_ASSERT(token_len);
    JADE_ASSERT(token_len > otp_ctx->digits);

    // Calculate otp hmac of counter (be) with the secret as the key
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    OTP_CHECK_BOOL_RETURN(prepare_md_ctx(otp_ctx, &md_ctx));

    const size_t hmac_last_index = mbedtls_md_get_size(md_ctx.md_info) - 1;
    JADE_ASSERT(hmac_last_index < MBEDTLS_SHA512_HMAC_LEN);

    // Counter to BE bytes
    uint8_t rcnt_buf[2 * sizeof(uint32_t)];
    JADE_ASSERT(sizeof(rcnt_buf) == sizeof(otp_ctx->counter));
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
    const int32_t trunc_code = full_code % (int32_t)pow(10, otp_ctx->digits);

    // Format as a string with leading 0's
    const int ret = snprintf(token, token_len, "%0*d", otp_ctx->digits, trunc_code);
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

    JADE_ASSERT(sizeof(key.priv_key) - 1 == AES_KEY_LEN_256);
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