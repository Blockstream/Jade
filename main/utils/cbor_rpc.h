#ifndef UTILS_CBOR_RPC_H_
#define UTILS_CBOR_RPC_H_

#include <cbor.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_crypto.h>
#include <wally_elements.h>

// RPC error codes
#define CBOR_RPC_INVALID_REQUEST -32600
#define CBOR_RPC_UNKNOWN_METHOD -32601
#define CBOR_RPC_BAD_PARAMETERS -32602
#define CBOR_RPC_INTERNAL_ERROR -32603

// Implementation specific error codes: -32000 to -32099
#define CBOR_RPC_USER_CANCELLED -32000
#define CBOR_RPC_PROTOCOL_ERROR -32001
#define CBOR_RPC_HW_LOCKED -32002

#define CBOR_RPC_TAG_PARAMS "params"
#define MAXLEN_ID 16

// Maximum expected/supported bip32 path length
// Plenty for green wallets, bip44 etc. with plenty to spare.
#define MAX_PATH_LEN 16

typedef struct {
    uint8_t asset_generator[ASSET_GENERATOR_LEN];
    uint8_t value_commitment[ASSET_COMMITMENT_LEN];
    uint8_t hmac[HMAC_SHA256_LEN];
    uint8_t asset_id[ASSET_TAG_LEN];
    uint64_t value;
    uint8_t blinding_key[EC_PUBLIC_KEY_LEN];
} commitment_t;

typedef struct {
    char id[MAXLEN_ID + 1];
    uint32_t path[MAX_PATH_LEN];
    size_t path_len;
    unsigned char signature_hash[SHA256_LEN];
    unsigned char sig[EC_SIGNATURE_DER_MAX_LEN + 1];
    size_t sig_size;
} signing_data_t;

bool cbor_print_error_for(const char* id, int code, const char* message, const uint8_t* data, size_t datalen,
    uint8_t* buffer, size_t buffer_len, size_t* towrite);

// Parse input
bool rpc_request_valid(const CborValue* request);
void rpc_get_id(const CborValue* value, char* data, size_t datalen, size_t* written);
void rpc_get_id_ptr(const CborValue* value, const char** data, size_t* written);
void rpc_get_method(const CborValue* value, const char** data, size_t* written);
bool rpc_is_method(const CborValue* value, const char* method);

// Some typed/checked getters for various nodes/data-types
bool rpc_has_field_data(const char* field, const CborValue* value);
void rpc_get_string(const char* field, size_t max, const CborValue* value, char* data, size_t* written);
void rpc_get_string_ptr(const char* field, const CborValue* value, const char** data, size_t* size);
void rpc_get_bytes(const char* field, size_t max, const CborValue* value, uint8_t* data, size_t* written);
void rpc_get_bytes_ptr(const char* field, const CborValue* value, const uint8_t** data, size_t* size);
void rpc_get_commitments_allocate(const char* field, const CborValue* value, commitment_t** data, size_t* written);
bool rpc_get_sizet(const char* field, const CborValue* value, size_t* res);
bool rpc_get_uint64_t(const char* field, const CborValue* value, uint64_t* res);
bool rpc_get_boolean(const char* field, const CborValue* value, bool* res);
bool rpc_get_bip32_path(
    const char* field, const CborValue* value, uint32_t* path_ptr, size_t max_path_len, size_t* written);
bool rpc_get_change(const char* field, const CborValue* value, CborValue* result);

// Build response objects
void rpc_init_cbor(CborEncoder* container, const char* id, size_t id_len);

void add_int_to_map(CborEncoder* container, const char* name, int64_t value);
void add_uint_to_map(CborEncoder* container, const char* name, uint64_t value);
void add_string_to_map(CborEncoder* container, const char* name, const char* value);
void add_string_sized_to_map(CborEncoder* container, const char* name, const char* value, size_t size);
void add_string_array_to_map(CborEncoder* container, const char* name, const char** texts, size_t len);
void add_bytes_to_map(CborEncoder* container, const char* name, const uint8_t* value, size_t len);
void add_boolean_to_map(CborEncoder* container, const char* name, bool value);
#endif /* UTILS_CBOR_RPC_H_ */
