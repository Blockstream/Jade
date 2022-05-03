#include "../jade_assert.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include <wally_elements.h>

#include "process_utils.h"

static void reply_commitments(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const commitment_t* commitments = (const commitment_t*)ctx;
    JADE_ASSERT(commitments->have_commitments);

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
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_commitments");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const char* errmsg = NULL;

    commitment_t commitments = { .have_commitments = false };

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

    // generate the abf
    if (!wallet_get_blinding_factor(hash_prevouts, hash_prevouts_len, output_index, ASSET_BLINDING_FACTOR,
            commitments.abf, sizeof(commitments.abf))) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute abf from the parameters", NULL);
    }

    // optional vbf provided by use to balance the blinded amounts
    size_t written = 0;
    rpc_get_bytes("vbf", sizeof(commitments.vbf), &params, commitments.vbf, &written);
    if (written) {
        if (written != sizeof(commitments.vbf)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract vbf from parameters", NULL);
            goto cleanup;
        }
    } else {
        // Otherwise compute vbf
        if (!wallet_get_blinding_factor(hash_prevouts, hash_prevouts_len, output_index, VALUE_BLINDING_FACTOR,
                commitments.vbf, sizeof(commitments.vbf))) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute vbf from the parameters", NULL);
            goto cleanup;
        }
    }

    // flip the asset_id for computing asset-generator
    uint8_t reversed_asset_id[sizeof(commitments.asset_id)];
    for (size_t i = 0; i < sizeof(commitments.asset_id); ++i) {
        reversed_asset_id[i] = commitments.asset_id[sizeof(commitments.asset_id) - 1 - i];
    }

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

    commitments.have_commitments = true;
    jade_process_reply_to_message_result(process->ctx, &commitments, reply_commitments);

    JADE_LOGI("Success");

cleanup:
    return;
}
