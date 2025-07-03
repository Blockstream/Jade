#ifndef AMALGAMATED_BUILD
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

    const ext_commitment_t* ec = (const ext_commitment_t*)ctx;
    const commitment_t* c = &ec->c;

    CborEncoder map_encoder; // result data
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 6);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "abf", c->abf, sizeof(c->abf));
    add_bytes_to_map(&map_encoder, "vbf", c->vbf, sizeof(c->vbf));
    add_bytes_to_map(&map_encoder, "asset_generator", ec->asset_generator, sizeof(ec->asset_generator));
    add_bytes_to_map(&map_encoder, "value_commitment", ec->value_commitment, sizeof(ec->value_commitment));
    add_bytes_to_map(&map_encoder, "asset_id", c->asset_id, sizeof(c->asset_id));
    add_uint_to_map(&map_encoder, "value", c->value);

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

    ext_commitment_t ec;

    if (!rpc_get_n_bytes("asset_id", &params, sizeof(ec.c.asset_id), ec.c.asset_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract asset_id from parameters");
        goto cleanup;
    }

    bool ret = rpc_get_uint64_t("value", &params, &ec.c.value);
    if (!ret) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract value from parameters");
        goto cleanup;
    }

    // hash-prevouts and output index are needed to generate deterministic blinding factors
    size_t hash_prevouts_len = 0;
    const uint8_t* hash_prevouts = NULL;
    size_t output_index = 0;
    if (!params_hashprevouts_outputindex(&params, &hash_prevouts, &hash_prevouts_len, &output_index, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        goto cleanup;
    }

    // optional vbf provided to balance the blinded amounts
    size_t vbf_len = 0;
    rpc_get_bytes("vbf", sizeof(ec.c.vbf), &params, ec.c.vbf, &vbf_len);
    if (vbf_len && vbf_len != sizeof(ec.c.vbf)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract vbf from parameters");
        goto cleanup;
    }

    // generate the abf (and vbf if necessary)
    uint8_t master_blinding_key[HMAC_SHA512_LEN];
    if (!params_get_master_blindingkey(&params, master_blinding_key, sizeof(master_blinding_key), &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        goto cleanup;
    }

    if (!vbf_len) {
        // Compute both abf and vbf
        JADE_STATIC_ASSERT(sizeof(ec.c.abf) + sizeof(ec.c.vbf) == WALLY_ABF_VBF_LEN);
        uint8_t tmp_abf_vbf[sizeof(ec.c.abf) + sizeof(ec.c.vbf)];
        if (!wallet_get_blinding_factor(master_blinding_key, sizeof(master_blinding_key), hash_prevouts,
                hash_prevouts_len, output_index, BF_ASSET_VALUE, tmp_abf_vbf, sizeof(tmp_abf_vbf))) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute abf/vbf from the parameters");
            goto cleanup;
        }
        memcpy(ec.c.abf, tmp_abf_vbf, sizeof(ec.c.abf));
        memcpy(ec.c.vbf, tmp_abf_vbf + sizeof(ec.c.abf), sizeof(ec.c.vbf));
    } else {
        // Compute abf only
        if (!wallet_get_blinding_factor(master_blinding_key, sizeof(master_blinding_key), hash_prevouts,
                hash_prevouts_len, output_index, BF_ASSET, ec.c.abf, sizeof(ec.c.abf))) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to compute abf from the parameters");
            goto cleanup;
        }
    }

    // flip the asset_id for computing asset-generator
    uint8_t reversed_asset_id[sizeof(ec.c.asset_id)];
    reverse(reversed_asset_id, ec.c.asset_id, sizeof(ec.c.asset_id));

    if (wally_asset_generator_from_bytes(reversed_asset_id, sizeof(reversed_asset_id), ec.c.abf, sizeof(ec.c.abf),
            ec.asset_generator, sizeof(ec.asset_generator))
        != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to build asset generator from the parameters");
        goto cleanup;
    }

    if (wally_asset_value_commitment(ec.c.value, ec.c.vbf, sizeof(ec.c.vbf), ec.asset_generator,
            sizeof(ec.asset_generator), ec.value_commitment, sizeof(ec.value_commitment))
        != WALLY_OK) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to build value commitment from the parameters");
        goto cleanup;
    }

    uint8_t buf[320];
    jade_process_reply_to_message_result(process->ctx, buf, sizeof(buf), &ec, reply_commitments);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
