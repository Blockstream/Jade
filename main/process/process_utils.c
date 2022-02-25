#include "../identity.h"
#include "../jade_assert.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "process_utils.h"

// Identity, curve and index are always needed by the 'identity' functions.
bool params_identity_curve_index(CborValue* params, const char** identity, size_t* identity_len, const char** curve,
    size_t* curve_len, size_t* index, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(identity);
    JADE_ASSERT(identity_len);
    JADE_ASSERT(curve);
    JADE_ASSERT(curve_len);
    JADE_ASSERT(index);
    JADE_ASSERT(errmsg);

    rpc_get_string_ptr("identity", params, identity, identity_len);
    if (!*identity || *identity_len >= MAX_DISPLAY_MESSAGE_LEN
        || !is_identity_protocol_valid(*identity, *identity_len)) {
        *errmsg = "Failed to extract valid identity from parameters";
        return false;
    }

    rpc_get_string_ptr("curve", params, curve, curve_len);
    if (!*curve || !is_identity_curve_valid(*curve, *curve_len)) {
        *errmsg = "Failed to extract valid curve name from parameters";
        return false;
    }

    // index is optional
    if (rpc_has_field_data("index", params)) {
        if (!rpc_get_sizet("index", params, index)) {
            *errmsg = "Failed to extract valid index from parameters";
            return false;
        }
    }

    return true;
}

// Hash-prevouts and output index are needed to generate deterministic blinding factors.
bool params_hashprevouts_outputindex(CborValue* params, const uint8_t** hash_prevouts, size_t* hash_prevouts_len,
    size_t* output_index, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(hash_prevouts);
    JADE_ASSERT(hash_prevouts_len);
    JADE_ASSERT(output_index);
    JADE_ASSERT(errmsg);

    rpc_get_bytes_ptr("hash_prevouts", params, hash_prevouts, hash_prevouts_len);
    if (*hash_prevouts_len != SHA256_LEN) {
        *errmsg = "Failed to extract hash_prevouts from parameters";
        return false;
    }

    if (!rpc_get_sizet("output_index", params, output_index)) {
        *errmsg = "Failed to extract output index from parameters";
        return false;
    }

    return true;
}
