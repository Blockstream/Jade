#include "../jade_assert.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/util.h"
#include "../wallet.h"

#include <wally_elements.h>

#include "process_utils.h"

static void reply_commitments(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const commitment_t* commitments = (const commitment_t*)ctx;
    JADE_ASSERT(commitments->content == (COMMITMENTS_ABF | COMMITMENTS_VBF | COMMITMENTS_INCLUDES_COMMITMENTS));

    CborEncoder map_encoder; // result data
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 6);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "abf", commitments->abf, sizeof(commitments->abf));
    add_bytes_to_map(&map_encoder, "vbf", commitments->vbf, sizeof(commitments->vbf));
    add_bytes_to_map(
        &map_encoder, "asset_generator", commitments->asset_generator, sizeof(commitments->asset_generator));
    add_bytes_to_map(
        &map_encoder, "value_commitment", commitments->value_commitment, sizeof(commitments->value_commitment));
    add_bytes_to_map(&map_encoder, "asset_id", commitments->asset_id, sizeof(commitments->asset_id));
    add_uint_to_map(&map_encoder, "value", commitments->value);

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_commitments_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_commitments");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const char* errmsg = NULL;

    commitment_t commitments = { .content = COMMITMENTS_NONE };

    if (!rpc_get_n_bytes("asset_id", &params, sizeof(commitments.asset_id), commitments.asset_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract asset_id from parameters", NULL);
        goto cleanup;
    }

    bool ret = rpc_get_uint64_t("value", &params, &commitments.value);
    if (!ret) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract value from parameters", NULL);
        goto cleanup;
    }

    // hash-prevouts and output index are needed to generate deterministic blinding factors
    size_t hash_prevouts_len = 0;
    const uint8_t* hash_prevouts = NULL;
    size_t output_index = 0;
    if (!params_hashprevouts_outputindex(&params, &hash_prevouts, &hash_prevouts_len, &output_index, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    // optional vbf provided to balance the blinded amounts
    size_t vbf_len = 0;
    rpc_get_bytes("vbf", sizeof(commitments.vbf), &params, commitments.vbf, &vbf_len);
    if (vbf_len && vbf_len != sizeof(commitments.vbf)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract vbf from parameters", NULL);
        goto cleanup;
    }

    // generate the abf (and vbf if necessary)
    uint8_t master_blinding_key[HMAC_SHA512_LEN];
    if (!params_get_master_blindingkey(&params, master_blinding_key, sizeof(master_blinding_key), &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    if (!vbf_len) {
        // Compute both abf and vbf
        JADE_STATIC_ASSERT(sizeof(commitments.abf) + sizeof(commitments.vbf) == WALLY_ABF_VBF_LEN);
        uint8_t tmp_abf_vbf[sizeof(commitments.abf) + sizeof(commitments.vbf)];
        if (!wallet_get_blinding_factor(master_blinding_key, sizeof(master_blinding_key), hash_prevouts,
                hash_prevouts_len, output_index, BF_ASSET_VALUE, tmp_abf_vbf, sizeof(tmp_abf_vbf))) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute abf/vbf from the parameters", NULL);
            goto cleanup;
        }
        memcpy(commitments.abf, tmp_abf_vbf, sizeof(commitments.abf));
        memcpy(commitments.vbf, tmp_abf_vbf + sizeof(commitments.abf), sizeof(commitments.vbf));
    } else {
        // Compute abf only
        if (!wallet_get_blinding_factor(master_blinding_key, sizeof(master_blinding_key), hash_prevouts,
                hash_prevouts_len, output_index, BF_ASSET, commitments.abf, sizeof(commitments.abf))) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute abf from the parameters", NULL);
            goto cleanup;
        }
    }

    // flip the asset_id for computing asset-generator
    uint8_t reversed_asset_id[sizeof(commitments.asset_id)];
    reverse(reversed_asset_id, commitments.asset_id, sizeof(commitments.asset_id));

    if (wally_asset_generator_from_bytes(reversed_asset_id, sizeof(reversed_asset_id), commitments.abf,
            sizeof(commitments.abf), commitments.asset_generator, sizeof(commitments.asset_generator))
        != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to build asset generator from the parameters", NULL);
        goto cleanup;
    }

    if (wally_asset_value_commitment(commitments.value, commitments.vbf, sizeof(commitments.vbf),
            commitments.asset_generator, sizeof(commitments.asset_generator), commitments.value_commitment,
            sizeof(commitments.value_commitment))
        != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to build value commitment from the parameters", NULL);
        goto cleanup;
    }

    commitments.content = COMMITMENTS_ABF | COMMITMENTS_VBF | COMMITMENTS_INCLUDES_COMMITMENTS;
    jade_process_reply_to_message_result(process->ctx, &commitments, reply_commitments);

    JADE_LOGI("Success");

cleanup:
    return;
}
