#ifndef IDENTITY_H_
#define IDENTITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline bool is_identity_protocol_ssh(const char* identity, const size_t identity_len)
{
    return identity_len > 6 && !memcmp(identity, "ssh://", 6);
}

static inline bool is_identity_protocol_gpg(const char* identity, const size_t identity_len)
{
    return identity_len > 6 && !memcmp(identity, "gpg://", 6);
}

static inline bool is_identity_protocol_valid(const char* identity, const size_t identity_len)
{
    return is_identity_protocol_ssh(identity, identity_len) || is_identity_protocol_gpg(identity, identity_len);
}

static inline bool is_key_type_slip0013(const char* type, const size_t type_len)
{
    return type_len == 9 && !memcmp(type, "slip-0013", 9);
}

static inline bool is_key_type_slip0017(const char* type, const size_t type_len)
{
    return type_len == 9 && !memcmp(type, "slip-0017", 9);
}

static inline bool is_key_type_valid(const char* type, const size_t type_len)
{
    return is_key_type_slip0013(type, type_len) || is_key_type_slip0017(type, type_len);
}

static inline bool is_identity_curve_nist256p1(const char* curve_name, const size_t curve_name_len)
{
    return curve_name_len == 9 && !memcmp(curve_name, "nist256p1", 9);
}

static inline bool is_identity_curve_valid(const char* curve_name, const size_t curve_name_len)
{
    return is_identity_curve_nist256p1(curve_name, curve_name_len);
}

bool get_identity_pubkey(const char* identity, size_t identity_len, size_t index, const char* curve, size_t curve_name,
    const char* type, size_t type_len, uint8_t* pubkey_out, size_t pubkey_out_len);

bool get_identity_shared_key(const char* identity, size_t identity_len, size_t index, const char* curve_name,
    size_t curve_name_len, const uint8_t* their_pubkey, size_t their_pubkey_len, uint8_t* output, size_t output_len);

bool sign_identity(const char* identity, size_t identity_len, size_t index, const char* curve_name,
    size_t curve_name_len, const uint8_t* challenge_hash, size_t challenge_hash_len, uint8_t* pubkey_out,
    size_t pubkey_out_len, uint8_t* signature_out, size_t signature_out_len);

#endif /* IDENTITY_H_ */
