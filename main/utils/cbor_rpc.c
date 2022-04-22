#include "cbor_rpc.h"
#include "jade_assert.h"
#include "utils/malloc_ext.h"
#include "wally_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLEN_METHOD 32

static const char* CBOR_RPC_TAG_METHOD = "method";
static const char* CBOR_RPC_TAG_ID = "id";

static const char* CBOR_RPC_TAG_RESULT = "result";
static const char* CBOR_RPC_TAG_ERROR = "error";
static const char* CBOR_RPC_TAG_CODE = "code";
static const char* CBOR_RPC_TAG_MESSAGE = "message";
static const char* CBOR_RPC_TAG_DATA = "data";

static const uint8_t CBOR_BINARY_MASK = 0b01000000;
static const uint8_t CBOR_TEXT_MASK = 0b01100000;
static const uint8_t CBOR_TYPE_MASK = 0b11100000;
static const uint8_t CBOR_LEN_MASK = 0b00011111;

static bool rpc_get_data(const char* field, const CborValue* value, CborValue* result)
{
    JADE_ASSERT(field);

    if (!value) {
        return false;
    }
    if (!cbor_value_is_valid(value)) {
        return false;
    }
    if (!cbor_value_is_map(value)) {
        return false;
    }

    CborError cberr = cbor_value_map_find_value(value, field, result);
    if (cberr != CborNoError) {
        return false;
    }

    const CborType restype = cbor_value_get_type(result);

    if (restype == CborInvalidType) {
        return false;
    }

    if (!cbor_value_is_valid(result)) {
        return false;
    }
    return true;
}

static void rpc_get_string_len(const char* field, const CborValue* value, size_t* written)
{
    CborValue result;
    JADE_ASSERT(*written == 0);
    const bool ok = rpc_get_data(field, value, &result);

    if (!ok || !cbor_value_is_text_string(&result)) {
        return;
    }

    size_t tmp_len = 0;
    CborError cberr;
    if (cbor_value_is_length_known(&result)) {
        cberr = cbor_value_get_string_length(&result, &tmp_len);
    } else {
        cberr = cbor_value_calculate_string_length(&result, &tmp_len);
    }

    if (cberr != CborNoError) {
        return;
    }

    *written = tmp_len;
}

bool rpc_request_valid(const CborValue* request)
{
    if (!request) {
        return false;
    }
    if (!cbor_value_is_valid(request)) {
        return false;
    }
    if (!cbor_value_is_map(request)) {
        return false;
    }

    size_t written = 0;
    rpc_get_string_len(CBOR_RPC_TAG_ID, request, &written);
    if (written == 0 || written > MAXLEN_ID) {
        return false;
    }
    written = 0;
    rpc_get_string_len(CBOR_RPC_TAG_METHOD, request, &written);
    if (written == 0 || written > MAXLEN_METHOD) {
        return false;
    }
    return true;
}

static uint8_t get_skip(const uint8_t lencode)
{
    /**
     * The value here indicates the size of the following varint-like data-length field.
     * <24 - Just skip this byte (as it contains the length)
     *  24 - Next byte is uint8_t for payload length, so skip 2 bytes (this and next one)
     *  25 - Next byte is uint16_t for payload length, so skip 3 bytes (this and next two)
     *  26 - Next byte is uint32_t for payload length, so skip 5 bytes (this and next four)
     *  27 is theoretically uint64_t but we are not expecting payloads in that size range!
     **/
    JADE_ASSERT(lencode < 27);
    if (lencode < 24) {
        return 1;
    } else if (lencode == 24) {
        return 2;
    } else if (lencode == 25) {
        return 3;
    } else if (lencode == 26) {
        return 5;
    }
    return 0;
}

static void rpc_get_type_ptr(
    const char* field, const CborValue* value, const uint8_t** data, size_t* size, uint8_t masktype)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(data);
    JADE_ASSERT(*size == 0);
    CborValue result;
    CborError cberr = cbor_value_map_find_value(value, field, &result);
    if (cberr != CborNoError || cbor_value_get_type(&result) == CborInvalidType || !cbor_value_is_valid(&result)) {
        *data = NULL;
        return;
    }

    const uint8_t* next_byte = cbor_value_get_next_byte(&result);
    const uint8_t typecode = *next_byte & CBOR_TYPE_MASK;
    if (typecode != masktype) {
        *data = NULL;
        return;
    }

    const uint8_t lencode = *next_byte & CBOR_LEN_MASK;

    *data = next_byte + get_skip(lencode);
    cberr = cbor_value_get_string_length(&result, size);
    JADE_ASSERT(cberr == CborNoError);
}

void rpc_get_bytes_ptr(const char* field, const CborValue* value, const uint8_t** data, size_t* size)
{
    rpc_get_type_ptr(field, value, data, size, CBOR_BINARY_MASK);
}

void rpc_get_bytes(const char* field, const size_t max, const CborValue* value, uint8_t* data, size_t* written)
{
    JADE_ASSERT(value);
    JADE_ASSERT(max > 0);
    JADE_ASSERT(data);
    JADE_ASSERT(*written == 0);
    CborValue result;
    const bool ok = rpc_get_data(field, value, &result);

    if (!ok || !cbor_value_is_byte_string(&result)) {
        return;
    }

    size_t tmp_len = 0;

    CborError cberr;
    if (cbor_value_is_length_known(&result)) {
        cberr = cbor_value_get_string_length(&result, &tmp_len);
    } else {
        cberr = cbor_value_calculate_string_length(&result, &tmp_len);
    }

    if (cberr != CborNoError) {
        return;
    }

    if (tmp_len > max) {
        return;
    }

    size_t local_written = max;

    cberr = cbor_value_copy_byte_string(&result, data, &local_written, NULL);
    JADE_ASSERT(cberr == CborNoError);
    JADE_ASSERT(local_written > 0);
    JADE_ASSERT(local_written <= max);
    *written = local_written;
}

void rpc_get_string_ptr(const char* field, const CborValue* value, const char** data, size_t* size)
{
    rpc_get_type_ptr(field, value, (const uint8_t**)data, size, CBOR_TEXT_MASK);
}

void rpc_get_string(const char* field, const size_t max, const CborValue* value, char* data, size_t* written)
{
    JADE_ASSERT(max > 0);
    JADE_ASSERT(data);
    CborValue result;
    JADE_ASSERT(*written == 0);
    const bool ok = rpc_get_data(field, value, &result);

    if (!ok || !cbor_value_is_text_string(&result)) {
        return;
    }

    size_t tmp_len = 0;
    CborError cberr;
    if (cbor_value_is_length_known(&result)) {
        cberr = cbor_value_get_string_length(&result, &tmp_len);
    } else {
        cberr = cbor_value_calculate_string_length(&result, &tmp_len);
    }

    if (cberr != CborNoError) {
        return;
    }

    // If tmp_len == max, the cbor_value_copy_text_string() function skips writing a NULL terminator.
    // Simpler to always ensure there is space, then the returned string is always null-terminated.
    if (tmp_len >= max) {
        return;
    }

    size_t local_written = max;

    cberr = cbor_value_copy_text_string(&result, data, &local_written, NULL);
    JADE_ASSERT(cberr == CborNoError);
    JADE_ASSERT(local_written < max); // local_written does not include null-terminator
    JADE_ASSERT(data[local_written] == '\0');
    *written = local_written;
}

bool rpc_get_boolean(const char* field, const CborValue* value, bool* res)
{
    JADE_ASSERT(value);
    JADE_ASSERT(res);
    CborValue result;
    return rpc_get_data(field, value, &result) && cbor_value_is_boolean(&result)
        && cbor_value_get_boolean(&result, res) == CborNoError;
}

bool rpc_get_uint64_t(const char* field, const CborValue* value, uint64_t* res)
{
    JADE_ASSERT(value);
    JADE_ASSERT(res);
    CborValue result;
    const bool ok = rpc_get_data(field, value, &result);

    if (!ok || !cbor_value_is_unsigned_integer(&result)) {
        return false;
    }
    const CborError cberr = cbor_value_get_uint64(&result, res);
    JADE_ASSERT(cberr == CborNoError);
    return true;
}

bool rpc_get_sizet(const char* field, const CborValue* value, size_t* res)
{
    JADE_ASSERT(value);
    JADE_ASSERT(res);
    CborValue result;
    const bool ok = rpc_get_data(field, value, &result);

    if (!ok || !cbor_value_is_unsigned_integer(&result)) {
        return false;
    }
    uint64_t tmp = 0;
    const CborError cberr = cbor_value_get_uint64(&result, &tmp);
    JADE_ASSERT(cberr == CborNoError);
    if (tmp > 0xFFFFFFFF) {
        return false;
    }
    *res = tmp & 0xFFFFFFFF;
    return true;
}

void rpc_get_method(const CborValue* value, const char** data, size_t* written)
{
    JADE_ASSERT(value);
    JADE_ASSERT(data);
    JADE_ASSERT(written);
    JADE_ASSERT(cbor_value_is_valid(value));
    JADE_ASSERT(cbor_value_is_map(value));
    rpc_get_string_ptr(CBOR_RPC_TAG_METHOD, value, data, written);
    JADE_ASSERT(*written <= MAXLEN_METHOD);
}

static bool rpc_key_equals(const CborValue* value, const char* key, const char* data)
{
    JADE_ASSERT(value);
    JADE_ASSERT(key);
    JADE_ASSERT(data);
    JADE_ASSERT(cbor_value_is_valid(value));
    JADE_ASSERT(cbor_value_is_map(value));

    CborValue result_value;

    CborError cberr = cbor_value_map_find_value(value, key, &result_value);

    JADE_ASSERT(cberr == CborNoError);

    const CborType restype = cbor_value_get_type(&result_value);

    JADE_ASSERT(restype != CborInvalidType);
    JADE_ASSERT(cbor_value_is_valid(&result_value));

    JADE_ASSERT(cbor_value_is_text_string(&result_value));

    bool result = false;
    cberr = cbor_value_text_string_equals(&result_value, data, &result);
    JADE_ASSERT(cberr == CborNoError);
    return result;
}

bool rpc_is_method(const CborValue* value, const char* method)
{
    return rpc_key_equals(value, CBOR_RPC_TAG_METHOD, method);
}

void rpc_get_id_ptr(const CborValue* value, const char** data, size_t* written)
{
    JADE_ASSERT(data);
    JADE_ASSERT(written);
    if (!value) {
        return;
    }
    rpc_get_string_ptr(CBOR_RPC_TAG_ID, value, data, written);
}

void rpc_get_id(const CborValue* value, char* data, const size_t datalen, size_t* written)
{
    JADE_ASSERT(data);
    JADE_ASSERT(datalen);
    JADE_ASSERT(written);
    if (!value) {
        return;
    }
    if (!cbor_value_is_valid(value)) {
        return;
    }
    if (!cbor_value_is_map(value)) {
        return;
    }

    rpc_get_string(CBOR_RPC_TAG_ID, datalen, value, data, written);
}

// Build response objects

static bool cbor_build_error_for(
    const char* id, int code, const char* message, const uint8_t* data, const size_t datalen, CborEncoder* container)
{
    JADE_ASSERT(id);
    JADE_ASSERT(strlen(id) <= MAXLEN_ID);
    JADE_ASSERT(container);

    CborEncoder root_map_encoder; // root (id, error)
    CborError cberr = cbor_encoder_create_map(container, &root_map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);
    add_string_to_map(&root_map_encoder, CBOR_RPC_TAG_ID, id);

    cberr = cbor_encode_text_stringz(&root_map_encoder, CBOR_RPC_TAG_ERROR);
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder error_map_encoder; // error (code, message, ?data)
    cberr = cbor_encoder_create_map(&root_map_encoder, &error_map_encoder, data ? 3 : 2);
    JADE_ASSERT(cberr == CborNoError);

    add_int_to_map(&error_map_encoder, CBOR_RPC_TAG_CODE, code);
    add_string_to_map(&error_map_encoder, CBOR_RPC_TAG_MESSAGE, message);

    if (data) {
        cberr = cbor_encode_text_stringz(&error_map_encoder, CBOR_RPC_TAG_DATA);
        JADE_ASSERT(cberr == CborNoError);
        cberr = cbor_encode_byte_string(&error_map_encoder, (uint8_t*)data, datalen);
        if (cberr != CborNoError) {
            cberr = cbor_encoder_close_container(&root_map_encoder, &error_map_encoder);
            if (cberr == CborNoError) {
                cbor_encoder_close_container(container, &root_map_encoder);
            }
            return false;
        }
    }

    cberr = cbor_encoder_close_container(&root_map_encoder, &error_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(container, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    return true;
}

bool cbor_print_error_for(const char* id, int code, const char* message, const uint8_t* data, const size_t datalen,
    uint8_t* buffer, const size_t buffer_len, size_t* towrite)
{
    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, buffer, buffer_len, 0);
    const bool res = cbor_build_error_for(id, code, message, data, datalen, &root_encoder);
    if (res) {
        *towrite = cbor_encoder_get_buffer_size(&root_encoder, buffer);
    }
    return res;
}

// Some typed/checked getters for various nodes/data-types

bool rpc_has_field_data(const char* field, const CborValue* value)
{
    CborValue result;
    return rpc_get_data(field, value, &result) && !cbor_value_is_null(&result);
}

bool rpc_get_array(const char* field, const CborValue* value, CborValue* result)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(result);
    return rpc_get_data(field, value, result) && cbor_value_is_array(result);
}

bool rpc_get_map(const char* field, const CborValue* value, CborValue* result)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(result);
    return rpc_get_data(field, value, result) && cbor_value_is_map(result);
}

static void reverse(uint8_t* buf, size_t len)
{
    // flip the order of the bytes in-place
    for (uint8_t *c1 = buf, *c2 = buf + len - 1; c1 < c2; ++c1, --c2) {
        const uint8_t tmp = *c1;
        *c1 = *c2;
        *c2 = tmp;
    }
}

void rpc_get_commitments_allocate(const char* field, const CborValue* value, commitment_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(data);
    JADE_ASSERT(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t array_len = 0;
    CborError cberr = cbor_value_get_array_length(&result, &array_len);
    if (cberr != CborNoError) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    commitment_t* const commitments = JADE_CALLOC(array_len, sizeof(commitment_t));

    size_t tmp = 0;
    for (size_t i = 0; i < array_len; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        commitment_t* const commitment = commitments + i;

        if (cbor_value_is_null(&arrayItem)) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!cbor_value_is_map(&arrayItem)) {
            free(commitments);
            return;
        }

        size_t map_length = 0;
        if (cbor_value_get_map_length(&arrayItem, &map_length) == CborNoError && map_length == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        tmp = 0;
        rpc_get_bytes(
            "asset_generator", sizeof(commitment->asset_generator), &arrayItem, commitment->asset_generator, &tmp);
        if (tmp != sizeof(commitment->asset_generator)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes(
            "value_commitment", sizeof(commitment->value_commitment), &arrayItem, commitment->value_commitment, &tmp);

        if (tmp != sizeof(commitment->value_commitment)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes("hmac", sizeof(commitment->hmac), &arrayItem, commitment->hmac, &tmp);

        if (tmp != sizeof(commitment->hmac)) {
            free(commitments);
            return;
        }
        tmp = 0;
        rpc_get_bytes("asset_id", sizeof(commitment->asset_id), &arrayItem, commitment->asset_id, &tmp);
        reverse(commitment->asset_id, sizeof(commitment->asset_id));

        if (tmp != sizeof(commitment->asset_id)) {
            free(commitments);
            return;
        }

        tmp = 0;
        rpc_get_bytes("blinding_key", sizeof(commitment->blinding_key), &arrayItem, commitment->blinding_key, &tmp);

        if (tmp != sizeof(commitment->blinding_key)) {
            free(commitments);
            return;
        }

        const bool retval = rpc_get_uint64_t("value", &arrayItem, &(commitment->value));
        if (!retval) {
            free(commitments);
            return;
        }

        // Set flag to show struct is populated/initialised
        commitment->have_commitments = true;

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(commitments);
        return;
    }

    *written = array_len;
    *data = commitments;
}

void rpc_get_signers_allocate(const char* field, const CborValue* value, signer_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(data);
    JADE_ASSERT(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t array_len = 0;
    CborError cberr = cbor_value_get_array_length(&result, &array_len);
    if (cberr != CborNoError) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    signer_t* const signers = JADE_MALLOC(array_len * sizeof(signer_t));

    size_t tmp = 0;
    for (size_t i = 0; i < array_len; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        signer_t* const signer = signers + i;

        if (!cbor_value_is_map(&arrayItem)) {
            free(signers);
            return;
        }

        size_t map_length = 0;
        if (cbor_value_get_map_length(&arrayItem, &map_length) == CborNoError && map_length == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        tmp = 0;
        rpc_get_bytes("fingerprint", sizeof(signer->fingerprint), &arrayItem, signer->fingerprint, &tmp);
        if (tmp != sizeof(signer->fingerprint)) {
            free(signers);
            return;
        }

        signer->derivation_len = 0;
        if (!rpc_get_bip32_path("derivation", &arrayItem, signer->derivation, MAX_PATH_LEN, &signer->derivation_len)) {
            free(signers);
            return;
        }

        signer->xpub_len = 0;
        rpc_get_string("xpub", sizeof(signer->xpub), &arrayItem, signer->xpub, &signer->xpub_len);
        if (signer->xpub_len == 0 || signer->xpub_len >= sizeof(signer->xpub)) {
            free(signers);
            return;
        }

        signer->path_len = 0;
        if (!rpc_get_bip32_path("path", &arrayItem, signer->path, MAX_PATH_LEN, &signer->path_len)) {
            free(signers);
            return;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(signers);
        return;
    }

    *written = array_len;
    *data = signers;
}

bool rpc_get_bip32_path(
    const char* field, const CborValue* value, uint32_t* path_ptr, const size_t max_path_len, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);

    CborValue result;
    return rpc_get_data(field, value, &result)
        && rpc_get_bip32_path_from_value(&result, path_ptr, max_path_len, written);
}

bool rpc_get_bip32_path_from_value(CborValue* value, uint32_t* path_ptr, const size_t max_path_len, size_t* written)
{
    JADE_ASSERT(value);
    JADE_ASSERT(path_ptr);
    JADE_ASSERT(max_path_len > 0);
    JADE_ASSERT(written);
    JADE_ASSERT(*written == 0);

    if (!cbor_value_is_array(value)) {
        return false;
    }
    size_t array_len = 0;
    CborError cberr = cbor_value_get_array_length(value, &array_len);

    if (cberr != CborNoError || array_len > max_path_len) {
        return false;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(value, &arrayItem);
    if (cberr != CborNoError) {
        return false;
    }

    uint64_t tmp = 0;
    for (size_t counter = 0; counter < array_len; ++counter) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        if (!cbor_value_is_unsigned_integer(&arrayItem)) {
            return false;
        }
        cberr = cbor_value_get_uint64(&arrayItem, &tmp);
        JADE_ASSERT(cberr == CborNoError);

        if (tmp > 0xFFFFFFFF) {
            return false;
        }
        path_ptr[counter] = tmp;

        cberr = cbor_value_advance_fixed(&arrayItem);
        JADE_ASSERT(cberr == CborNoError);
    }

    JADE_ASSERT(cbor_value_at_end(&arrayItem));

    cberr = cbor_value_leave_container(value, &arrayItem);
    if (cberr != CborNoError) {
        return false;
    }
    *written = array_len;
    return true;
}

void rpc_init_cbor(CborEncoder* map_container, const char* id, size_t id_len)
{
    JADE_ASSERT(map_container);
    JADE_ASSERT(id);
    JADE_ASSERT(id_len);
    add_string_sized_to_map(map_container, CBOR_RPC_TAG_ID, id, id_len);
    const CborError cberr = cbor_encode_text_stringz(map_container, CBOR_RPC_TAG_RESULT);
    JADE_ASSERT(cberr == CborNoError);
}

void add_uint_to_map(CborEncoder* container, const char* name, const uint64_t value)
{
    JADE_ASSERT(container);
    JADE_ASSERT(name);
    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_uint(container, value);
    JADE_ASSERT(cberr == CborNoError);
}

void add_int_to_map(CborEncoder* container, const char* name, const int64_t value)
{
    JADE_ASSERT(container);
    JADE_ASSERT(name);
    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_int(container, value);
    JADE_ASSERT(cberr == CborNoError);
}

void add_string_to_map(CborEncoder* container, const char* name, const char* value)
{
    JADE_ASSERT(container);
    JADE_ASSERT(name);
    JADE_ASSERT(value);

    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_text_stringz(container, value);
    JADE_ASSERT(cberr == CborNoError);
}

void add_string_sized_to_map(CborEncoder* container, const char* name, const char* value, size_t size)
{
    JADE_ASSERT(container);
    JADE_ASSERT(name);
    JADE_ASSERT(value);
    JADE_ASSERT(size);

    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_text_string(container, value, size);
    JADE_ASSERT(cberr == CborNoError);
}

void add_string_array_to_map(CborEncoder* container, const char* name, const char** texts, const size_t len)
{
    JADE_ASSERT(name);
    JADE_ASSERT(container);
    JADE_ASSERT(texts);
    JADE_ASSERT((texts && len) || (texts == NULL && len == 0));

    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder array_encoder;
    cberr = cbor_encoder_create_array(container, &array_encoder, len);
    JADE_ASSERT(cberr == CborNoError);

    for (int i = 0; i < len; ++i) {
        const char* value = texts[i];
        JADE_ASSERT(value);
        cberr = cbor_encode_text_stringz(&array_encoder, value);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &array_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void add_bytes_to_map(CborEncoder* container, const char* name, const uint8_t* value, const size_t len)
{
    JADE_ASSERT(container);
    JADE_ASSERT(name);
    JADE_ASSERT((value && len) || (value == NULL && len == 0));

    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_byte_string(container, value, len);
    JADE_ASSERT(cberr == CborNoError);
}

void add_boolean_to_map(CborEncoder* container, const char* name, const bool value)
{
    JADE_ASSERT(name);
    JADE_ASSERT(container);
    CborError cberr = cbor_encode_text_stringz(container, name);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_boolean(container, value);
    JADE_ASSERT(cberr == CborNoError);
}
