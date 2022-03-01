#include "../jade_assert.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include <wally_elements.h>

#include "process_utils.h"

static void reverse(uint8_t* buf, size_t len)
{
    // flip the order of the bytes in-place
    for (uint8_t *c1 = buf, *c2 = buf + len - 1; c1 < c2; ++c1, --c2) {
        const uint8_t tmp = *c1;
        *c1 = *c2;
        *c2 = tmp;
    }
}

void get_commitments_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    const char* reqid = NULL;
    ASSERT_CURRENT_MESSAGE(process, "get_commitments");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    uint8_t asset_id[ASSET_TAG_LEN];
    size_t asset_id_len = 0;
    rpc_get_bytes("asset_id", ASSET_TAG_LEN, &params, asset_id, &asset_id_len);
    if (asset_id_len != ASSET_TAG_LEN) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract asset_id from parameters", NULL);
        goto cleanup;
    }

    // flip the asset_id
    reverse(asset_id, sizeof(asset_id));

    uint64_t value = 0;
    bool retval = rpc_get_uint64_t("value", &params, &value);
    if (!retval) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract value from parameters", NULL);
        goto cleanup;
    }

    // needed to generate the blinding factors deterministically
    uint32_t hash_prevouts_len = 0;
    const uint8_t* hash_prevouts = NULL;
    rpc_get_bytes_ptr("hash_prevouts", &params, &hash_prevouts, &hash_prevouts_len);
    if (hash_prevouts_len != SHA256_LEN) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract hash_prevouts from parameters", NULL);
        goto cleanup;
    }

    uint32_t output_index = 0;
    retval = rpc_get_sizet("output_index", &params, &output_index);
    if (!retval) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract output index from parameters", NULL);
        goto cleanup;
    }

    // generate the abf
    uint8_t abf[HMAC_SHA256_LEN];
    if (!wallet_get_blinding_factor(
            hash_prevouts, hash_prevouts_len, output_index, ASSET_BLINDING_FACTOR, abf, sizeof(abf))) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute abf from the parameters", NULL);
    }

    // optional vbf provided by use to balance the blinded amounts
    uint8_t vbf[HMAC_SHA256_LEN];
    size_t written = 0;
    rpc_get_bytes("vbf", HMAC_SHA256_LEN, &params, vbf, &written);
    if (written > 0) {
        if (written != HMAC_SHA256_LEN) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract vbf from parameters", NULL);
            goto cleanup;
        }
    } else {
        JADE_ASSERT(written == 0);
        // Otherwise compute vbf
        if (!wallet_get_blinding_factor(
                hash_prevouts, hash_prevouts_len, output_index, VALUE_BLINDING_FACTOR, vbf, sizeof(vbf))) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute vbf from the parameters", NULL);
            goto cleanup;
        }
    }

    // compute asset generator and value commitment and place them into the signed blob
    // signed_blob = <asset_generator> + <value_commitment> + <plaintext asset id> + <plaintext value>
    uint8_t signed_blob[ASSET_GENERATOR_LEN + ASSET_COMMITMENT_LEN + ASSET_TAG_LEN + sizeof(uint64_t)];

    uint8_t* asset_generator = signed_blob;
    if (wally_asset_generator_from_bytes(
            asset_id, asset_id_len, abf, HMAC_SHA256_LEN, asset_generator, ASSET_GENERATOR_LEN)
        != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to build asset generator from the parameters", NULL);
        goto cleanup;
    }

    uint8_t* value_commitment = asset_generator + ASSET_GENERATOR_LEN;
    if (wally_asset_value_commitment(
            value, vbf, HMAC_SHA256_LEN, asset_generator, ASSET_GENERATOR_LEN, value_commitment, ASSET_COMMITMENT_LEN)
        != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to build value commitment from the parameters", NULL);
        goto cleanup;
    }

    // copy value and asset_id into the signed blob
    uint8_t* signed_asset_id_copy = value_commitment + ASSET_COMMITMENT_LEN;
    memcpy(signed_asset_id_copy, asset_id, ASSET_TAG_LEN);

    uint8_t* signed_value_copy = signed_asset_id_copy + ASSET_TAG_LEN;
    memcpy(signed_value_copy, &value,
        sizeof(uint64_t)); // TODO endianness? should be fine as long as we encode/decode always on the same platform

    // hmac the result
    uint8_t hmac[HMAC_SHA256_LEN];
    if (!wallet_hmac_with_master_key(signed_blob, sizeof(signed_blob), hmac, sizeof(hmac))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to compute hmac", NULL);
        goto cleanup;
    }

    uint8_t buf[512];
    // create output
    CborEncoder root_encoder;

    cbor_encoder_init(&root_encoder, buf, sizeof(buf), 0);

    CborEncoder root_map_encoder; // id, result
    CborEncoder map_encoder; // result data

    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    written = 0;
    rpc_get_id_ptr(&process->ctx.value, &reqid, &written);
    JADE_ASSERT(written != 0);
    rpc_init_cbor(&root_map_encoder, reqid, written);

    cberr = cbor_encoder_create_map(&root_map_encoder, &map_encoder, 7);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "abf", abf, HMAC_SHA256_LEN);
    add_bytes_to_map(&map_encoder, "vbf", vbf, HMAC_SHA256_LEN);
    add_bytes_to_map(&map_encoder, "asset_generator", asset_generator, ASSET_GENERATOR_LEN);
    add_bytes_to_map(&map_encoder, "value_commitment", value_commitment, ASSET_COMMITMENT_LEN);
    add_bytes_to_map(&map_encoder, "hmac", hmac, HMAC_SHA256_LEN);
    reverse(asset_id, sizeof(asset_id));
    add_bytes_to_map(&map_encoder, "asset_id", asset_id, ASSET_TAG_LEN);
    add_uint_to_map(&map_encoder, "value", value);

    cberr = cbor_encoder_close_container(&root_map_encoder, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t towrite = cbor_encoder_get_buffer_size(&root_encoder, buf);
    jade_process_push_out_message(buf, towrite, process->ctx.source);
    JADE_LOGI("Success");

cleanup:
    return;
}
