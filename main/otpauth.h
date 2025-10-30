#ifndef OTPAUTH_H_
#define OTPAUTH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OTP_MAX_NAME_LEN 16
#define OTP_MAX_URI_LEN 256
#define OTP_MAX_TOKEN_LEN 12

#define OTP_MAX_RECORDS 16

#define OTP_SCHEMA "otpauth"
#define OTP_SCHEMA_FULL "otpauth://"

typedef struct otpauth_ctx {
    uint64_t counter;
    enum { MDTYPE_NONE = 0, MDTYPE_SHA1, MDTYPE_SHA256, MDTYPE_SHA512 } md_type;
    enum { OTPTYPE_NONE = 0, OTPTYPE_HOTP, OTPTYPE_TOTP } otp_type;
    const char* name;

    // The uri string fragments
    const char* type;
    const char* label;
    const char* secret;
    const char* issuer;
    size_t type_len;
    size_t label_len;
    size_t secret_len;
    size_t issuer_len;
    int8_t digits;
    int8_t period;
} otpauth_ctx_t;

typedef enum { OTP_ERR_OK, OTP_ERR_TOTP_TIME, OTP_ERR_HOTP_COUNTER } otp_err_t;

bool otp_is_valid(const otpauth_ctx_t* otp_ctx);

// Parse the otp uri into a context object
bool otp_uri_to_ctx(const char* uri, size_t uri_len, otpauth_ctx_t* otp_ctx);

// Update the context object with an explicit or default/calculated nonce value
void otp_set_explicit_value(otpauth_ctx_t* otp_ctx, int64_t value);
otp_err_t otp_set_default_value(otpauth_ctx_t* otp_ctx, uint64_t* value_out);

// Get the auth code for the given context
bool otp_get_auth_code(const otpauth_ctx_t* otp_ctx, char* token, size_t token_len);

// Functions to deal with uri encryption and persistence
// NOTE: otp_name must be nul-terminated, uri does not
bool otp_save_uri(const char* otp_name, const char* uri, size_t uri_len);
bool otp_load_uri(const char* otp_name, char* uri, size_t uri_len, size_t* written);

#endif /* OTPAUTH_H_ */
