#ifndef AMALGAMATED_BUILD
#include "sign_utils.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../ui/sign_tx.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../utils/temporary_stack.h"
#include "../utils/util.h"

#include <sodium/utils.h>
#include <wally_elements.h>

#include "process_utils.h"

static const char TX_TYPE_STR_SWAP[] = "swap";
static const char TX_TYPE_STR_SEND_PAYMENT[] = "send_payment";

// Map a txtype string to an enum value
#define TX_TYPE_STR_MATCH(typestr) ((len == sizeof(typestr) - 1 && !strncmp(type, typestr, sizeof(typestr) - 1)))
static bool rpc_get_txtype(jade_process_t* process, CborValue* value, TxType_t* txtype)
{
    const char* type = NULL;
    size_t len = 0;
    rpc_get_string_ptr("tx_type", value, &type, &len);
    if (!type || !len) {
        *txtype = TXTYPE_SEND_PAYMENT;
        return true; // Not present, treat as a payment
    }
    if (TX_TYPE_STR_MATCH(TX_TYPE_STR_SWAP)) {
        *txtype = TXTYPE_SWAP;
        return true;
    } else if (TX_TYPE_STR_MATCH(TX_TYPE_STR_SEND_PAYMENT)) {
        *txtype = TXTYPE_SEND_PAYMENT;
        return true;
    }
    return false; // Unknown tx_type
}

static void rpc_get_asset_summary(
    jade_process_t* process, const char* field, const CborValue* value, asset_summary_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_INIT_OUT_PPTR(data);
    JADE_INIT_OUT_SIZE(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t num_array_items = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_array_items);
    if (cberr != CborNoError || !num_array_items) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    asset_summary_t* const sums = JADE_CALLOC(num_array_items, sizeof(asset_summary_t));
    jade_process_free_on_exit(process, sums);

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        asset_summary_t* const item = sums + i;

        if (!cbor_value_is_map(&arrayItem)
            || !rpc_get_n_bytes("asset_id", &arrayItem, sizeof(item->asset_id), item->asset_id)
            || !rpc_get_uint64_t("satoshi", &arrayItem, &item->value)) {
            return;
        }

        cberr = cbor_value_advance(&arrayItem);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr == CborNoError) {
        *written = num_array_items;
        *data = sums;
    }
}

static bool validate_additional_info(jade_process_t* process, const struct wally_tx* tx, const TxType_t txtype,
    const bool is_partial, const asset_summary_t* in_sums, const size_t num_in_sums, const asset_summary_t* out_sums,
    const size_t num_out_sums)
{
    const char* errmsg = NULL;
    // Shouldn't have pointers to empty arrays
    JADE_ASSERT(!in_sums == !num_in_sums);
    JADE_ASSERT(!out_sums == !num_out_sums);

    // Validate tx type data
    if (txtype == TXTYPE_SWAP) {
        // Input and output summary must be present - they will be fully validated later
        if (!in_sums || !out_sums) {
            errmsg = "Swap tx missing input/output summary information";
            goto done;
        }

        // Validate swap or proposal appears to have expected inputs and outputs
        if (is_partial) {
            // At this time the only 'partial swap' we accept is an initial proposal with exactly one
            // input and exactly one output which is to self, and in a different asset to the input
            if (tx->num_inputs != 1 || tx->num_outputs != 1 || num_in_sums != 1 || num_out_sums != 1
                || !memcmp(in_sums[0].asset_id, out_sums[0].asset_id, sizeof(out_sums[0].asset_id))) {
                errmsg = "Initial swap proposal must have single wallet input and output in different assets";
                goto done;
            }
        } else {
            // TODO: Ideally check total number of assets in our inputs and outputs
            if (tx->num_inputs < 2 || tx->num_outputs < 2) {
                errmsg = "Insufficient inputs/outputs for a swap tx";
                goto done;
            }
        }
    } else if (txtype != TXTYPE_SEND_PAYMENT) {
        errmsg = "Unsupported tx-type in additional info";
        goto done;
    }
done:
    if (errmsg) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        return false;
    }
    return true;
}

TxType_t params_additional_info(jade_process_t* process, CborValue* params, const struct wally_tx* tx, TxType_t* txtype,
    bool* is_partial, asset_summary_t** in_sums, size_t* num_in_sums, asset_summary_t** out_sums, size_t* num_out_sums)
{
    JADE_ASSERT(params);
    JADE_ASSERT(tx);
    JADE_ASSERT(txtype);
    JADE_ASSERT(is_partial);
    JADE_INIT_OUT_PPTR(in_sums);
    JADE_INIT_OUT_SIZE(num_in_sums);
    JADE_INIT_OUT_PPTR(out_sums);
    JADE_INIT_OUT_SIZE(num_out_sums);

    *is_partial = false;
    *txtype = TXTYPE_SEND_PAYMENT;

    // If no 'additional_info' passed, assume this is a a simple send-payment 'classic' tx
    CborValue additional_info;
    if (!rpc_get_map("additional_info", params, &additional_info)) {
        return true;
    }

    // input/output summaries required for some complex txn types, eg. swaps
    rpc_get_asset_summary(process, "wallet_input_summary", &additional_info, in_sums, num_in_sums);
    rpc_get_asset_summary(process, "wallet_output_summary", &additional_info, out_sums, num_out_sums);

    // 'partial' flag (defaults to false, set above)
    rpc_get_boolean("is_partial", &additional_info, is_partial);

    // Tx Type
    if (!rpc_get_txtype(process, &additional_info, txtype)) {
        return false;
    }
    if (!validate_additional_info(
            process, tx, *txtype, *is_partial, *in_sums, *num_in_sums, *out_sums, *num_out_sums)) {
        return false;
    }
    return true;
}

bool asset_summary_update(asset_summary_t* sums, const size_t num_sums, const uint8_t* asset_id,
    const size_t asset_id_len, const uint64_t value)
{
    if (!sums) {
        return true; // Nothing to do
    }
    JADE_ASSERT(asset_id);
    JADE_ASSERT(asset_id_len == sizeof(sums[0].asset_id));

    // Add passed sats amount to the first record found with matching asset_id
    for (size_t i = 0; i < num_sums; ++i) {
        if (!memcmp(asset_id, sums[i].asset_id, sizeof(sums[i].asset_id))) {
            sums[i].validated_value += value;
            return true;
        }
    }
    return false;
}

bool asset_summary_validate(asset_summary_t* sums, const size_t num_sums)
{
    JADE_ASSERT(!sums == !num_sums);

    // Check every asset record (if any) has been fully validated
    for (size_t i = 0; i < num_sums; ++i) {
        if (sums[i].value != sums[i].validated_value) {
            char* asset_id_hex = NULL;
            wally_hex_from_bytes(sums[i].asset_id, sizeof(sums[i].asset_id), &asset_id_hex);
            JADE_LOGW("Failed to validate input/output summary for %s", asset_id_hex);
            JADE_WALLY_VERIFY(wally_free_string(asset_id_hex));
            return false;
        }
    }
    return true;
}

bool get_commitment_data(CborValue* item, commitment_t* commitment)
{
    JADE_ASSERT(item);
    JADE_ASSERT(commitment);

    commitment->content = COMMITMENTS_NONE;

    // Need abf or asset_blind_proof
    if (rpc_get_n_bytes("abf", item, sizeof(commitment->abf), commitment->abf)) {
        commitment->content |= COMMITMENTS_ABF;
    }

    if (rpc_get_n_bytes(
            "asset_blind_proof", item, sizeof(commitment->asset_blind_proof), commitment->asset_blind_proof)) {
        commitment->content |= COMMITMENTS_ASSET_BLIND_PROOF;
    }

    if (!(commitment->content & (COMMITMENTS_ABF | COMMITMENTS_ASSET_BLIND_PROOF))) {
        return false;
    }

    // Need vbf or value_blind_proof
    if (rpc_get_n_bytes("vbf", item, sizeof(commitment->vbf), commitment->vbf)) {
        commitment->content |= COMMITMENTS_VBF;
    }

    size_t written = 0;
    rpc_get_bytes(
        "value_blind_proof", sizeof(commitment->value_blind_proof), item, commitment->value_blind_proof, &written);
    if (written && written <= sizeof(commitment->value_blind_proof)) {
        commitment->value_blind_proof_len = written;
        commitment->content |= COMMITMENTS_VALUE_BLIND_PROOF;
    }

    if (!(commitment->content & (COMMITMENTS_VBF | COMMITMENTS_VALUE_BLIND_PROOF))) {
        return false;
    }

    if (!rpc_get_n_bytes("asset_id", item, sizeof(commitment->asset_id), commitment->asset_id)) {
        return false;
    }

    if (!rpc_get_uint64_t("value", item, &commitment->value)) {
        return false;
    }

    // Blinding key is optional in some scenarios
    if (rpc_get_n_bytes("blinding_key", item, sizeof(commitment->blinding_key), commitment->blinding_key)) {
        commitment->content |= COMMITMENTS_BLINDING_KEY;
    }

    // Actual commitments are optional - but must be both commitments or neither.
    // If both are passed these will be copied into the tx and signed.
    // If not passed, the above blinding factors/proofs must match what is already present in the transaction output.
    // Must be both or neither - error if only one commitment passed.
    if (rpc_has_field_data("asset_generator", item) || rpc_has_field_data("value_commitment", item)) {
        if (!rpc_get_n_bytes(
                "asset_generator", item, sizeof(commitment->asset_generator), commitment->asset_generator)) {
            return false;
        }

        if (!rpc_get_n_bytes(
                "value_commitment", item, sizeof(commitment->value_commitment), commitment->value_commitment)) {
            return false;
        }

        // Set flag to show struct is fully populated/initialised, including commitments to sign.
        commitment->content |= COMMITMENTS_INCLUDES_COMMITMENTS;
    }

    return true;
}

bool params_trusted_commitments(
    jade_process_t* process, const CborValue* params, const struct wally_tx* tx, commitment_t** data)
{
    JADE_ASSERT(process);
    JADE_ASSERT(params);
    JADE_ASSERT(tx);
    JADE_INIT_OUT_PPTR(data);

    const char* errmsg = NULL;

    CborValue result;
    if (!rpc_get_array("trusted_commitments", params, &result)) {
        errmsg = "Failed to extract trusted commitments from parameters";
        goto cleanup;
    }

    // Expect one commitment element in the array for each output.
    // (Can be null/zero's for unblinded outputs.)
    size_t num_array_items = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_array_items);
    if (cberr != CborNoError || !num_array_items || num_array_items != tx->num_outputs) {
        errmsg = "Unexpected number of trusted commitments for transaction";
        goto cleanup;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        errmsg = "Invalid trusted commitments for transaction";
        goto cleanup;
    }

    commitment_t* const commitments = JADE_CALLOC(num_array_items, sizeof(commitment_t));
    jade_process_free_on_exit(process, commitments);

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        commitments[i].content = COMMITMENTS_NONE;

        if (cbor_value_is_null(&arrayItem)) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!cbor_value_is_map(&arrayItem)) {
            errmsg = "Invalid trusted commitments for transaction";
            goto cleanup;
        }

        size_t num_map_items = 0;
        if (cbor_value_get_map_length(&arrayItem, &num_map_items) == CborNoError && num_map_items == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        // Populate commitments data
        if (!get_commitment_data(&arrayItem, &commitments[i])) {
            errmsg = "Invalid trusted commitments for transaction";
            goto cleanup;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr == CborNoError) {
        *data = commitments;
    } else {
        errmsg = "Invalid trusted commitments for transaction";
    }

cleanup:
    if (errmsg) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        return false;
    }
    return true;
}

#ifdef CONFIG_SPIRAM
// Workaround to run 'wally_explicit_surjectionproof_verify()' and 'wally_explicit_rangeproof_verify()'
// on a temporary stack, as the underlying libsecp calls require over 50kb of stack space.
// NOTE: devices without SPIRAM do not have sufficient free memory to be able to do this verification,
// so atm we exclude it for those devices.
static bool verify_explicit_proofs(void* ctx)
{
    JADE_ASSERT(ctx);

    const commitment_t* commitments = (const commitment_t*)ctx;
    JADE_ASSERT(commitments->content & (COMMITMENTS_ASSET_BLIND_PROOF | COMMITMENTS_VALUE_BLIND_PROOF));
    JADE_ASSERT(commitments->content & COMMITMENTS_INCLUDES_COMMITMENTS);

    if (commitments->content & COMMITMENTS_ASSET_BLIND_PROOF) {
        uint8_t reversed_asset_id[sizeof(commitments->asset_id)];
        reverse(reversed_asset_id, commitments->asset_id, sizeof(commitments->asset_id));

        // NOTE: Appears to require ~52kb of stack space
        if (wally_explicit_surjectionproof_verify(commitments->asset_blind_proof,
                sizeof(commitments->asset_blind_proof), reversed_asset_id, sizeof(reversed_asset_id),
                commitments->asset_generator, sizeof(commitments->asset_generator))
            != WALLY_OK) {
            // Failed to verify explicit asset proof
            return false;
        }
    }

    if (commitments->content & COMMITMENTS_VALUE_BLIND_PROOF) {
        // NOTE: Appears to require ~40kb of stack space
        if (wally_explicit_rangeproof_verify(commitments->value_blind_proof, commitments->value_blind_proof_len,
                commitments->value, commitments->value_commitment, sizeof(commitments->value_commitment),
                commitments->asset_generator, sizeof(commitments->asset_generator))
            != WALLY_OK) {
            // Failed to verify explicit value proof
            return false;
        }
    }

    return true;
}
#endif // CONFIG_SPIRAM

bool verify_commitment_consistent(const commitment_t* commitments, const char** errmsg)
{
    JADE_ASSERT(commitments);
    JADE_INIT_OUT_PPTR(errmsg);

    if (!(commitments->content & COMMITMENTS_INCLUDES_COMMITMENTS)) {
        *errmsg = "Failed to extract final commitment values from commitments data";
        return false;
    }

    if (!(commitments->content & (COMMITMENTS_ABF | COMMITMENTS_ASSET_BLIND_PROOF))
        || !(commitments->content & (COMMITMENTS_VBF | COMMITMENTS_VALUE_BLIND_PROOF))) {
        *errmsg = "Failed to extract blinding factors or proofs from commitments data";
        return false;
    }

    // 1. Asset generator
    // If passed the abf, check the blinded asset commitment can be reconstructed
    // (ie. from the given reversed asset_id and abf)
    if (commitments->content & COMMITMENTS_ABF) {
        uint8_t reversed_asset_id[sizeof(commitments->asset_id)];
        reverse(reversed_asset_id, commitments->asset_id, sizeof(commitments->asset_id));

        uint8_t generator_tmp[sizeof(commitments->asset_generator)];
        if (wally_asset_generator_from_bytes(reversed_asset_id, sizeof(reversed_asset_id), commitments->abf,
                sizeof(commitments->abf), generator_tmp, sizeof(generator_tmp))
                != WALLY_OK
            || sodium_memcmp(commitments->asset_generator, generator_tmp, sizeof(generator_tmp)) != 0) {
            *errmsg = "Failed to verify blinded asset generator from commitments data";
            return false;
        }
    }

    // 2. Value commitment
    // If passed the vbf, check the blinded value commitment can be reconstructed
    // (ie. from the given value, asset_generator and vbf)
    if (commitments->content & COMMITMENTS_VBF) {
        uint8_t commitment_tmp[sizeof(commitments->value_commitment)];
        if (wally_asset_value_commitment(commitments->value, commitments->vbf, sizeof(commitments->vbf),
                commitments->asset_generator, sizeof(commitments->asset_generator), commitment_tmp,
                sizeof(commitment_tmp))
                != WALLY_OK
            || sodium_memcmp(commitments->value_commitment, commitment_tmp, sizeof(commitment_tmp)) != 0) {
            *errmsg = "Failed to verify blinded value commitment from commitments data";
            return false;
        }
    }

    // Verify any blinded proofs
    // NOTE: only a device with SPIRAM has sufficient memory to be able to do this verification.
    if (commitments->content & (COMMITMENTS_ASSET_BLIND_PROOF | COMMITMENTS_VALUE_BLIND_PROOF)) {
#ifdef CONFIG_SPIRAM
        // Because the libsecp calls 'secp256k1_surjectionproof_verify()' and 'secp256k1_rangeproof_verify()'
        // requires more stack space than is available to the main task, we run that function in a temporary task.
        const size_t stack_size = 54 * 1024; // 54kb seems sufficient
        if (!run_in_temporary_task(stack_size, verify_explicit_proofs, (void*)commitments)) {
            *errmsg = "Failed to verify explicit asset/value commitment proofs";
            return false;
        }
#else
        *errmsg = "Devices without external SPIRAM are unable to verify explicit proofs";
        return false;
#endif // CONFIG_SPIRAM
    }
    return true;
}

static bool add_output_info(
    commitment_t* commitments, const struct wally_tx_output* txoutput, output_info_t* outinfo, const char** errmsg)
{
    JADE_ASSERT(commitments);
    JADE_ASSERT(txoutput);
    JADE_ASSERT(outinfo);
    JADE_INIT_OUT_PPTR(errmsg);

    JADE_ASSERT(!(outinfo->flags & (OUTPUT_FLAG_CONFIDENTIAL | OUTPUT_FLAG_HAS_UNBLINDED)));
    if (commitments->content != COMMITMENTS_NONE) {
        // Output to be confidential/blinded, use the commitments data
        outinfo->flags |= (OUTPUT_FLAG_CONFIDENTIAL | OUTPUT_FLAG_HAS_UNBLINDED);

        // 1. Sanity checks
        if (txoutput->asset_len != sizeof(commitments->asset_generator)) {
            *errmsg = "Invalid asset generator in tx output";
            return false;
        }
        if (txoutput->value_len != sizeof(commitments->value_commitment)) {
            *errmsg = "Invalid value commitment in tx output";
            return false;
        }

        // 2. If passed explicit commitments copy them into the transaction output ready for signing
        // If not, copy the values from the tx into the commitment structure.
        // ie. so in any case commitment struct is complete, and reflects what is in the tx output
        if (commitments->content & COMMITMENTS_INCLUDES_COMMITMENTS) {
            memcpy(txoutput->asset, commitments->asset_generator, sizeof(commitments->asset_generator));
            memcpy(txoutput->value, commitments->value_commitment, sizeof(commitments->value_commitment));
        } else {
            memcpy(commitments->asset_generator, txoutput->asset, sizeof(commitments->asset_generator));
            memcpy(commitments->value_commitment, txoutput->value, sizeof(commitments->value_commitment));
            commitments->content |= COMMITMENTS_INCLUDES_COMMITMENTS;
        }

        // 3. Check the asset generator and value commitment can be reconstructed
        if (!verify_commitment_consistent(commitments, errmsg)) {
            // errmsg populated by call if failure
            return false;
        }

        // 4. Fetch the asset_id, value, and optional blinding_key into the info struct
        JADE_STATIC_ASSERT(sizeof(outinfo->asset_id) == sizeof(commitments->asset_id));
        memcpy(outinfo->asset_id, commitments->asset_id, sizeof(commitments->asset_id));
        outinfo->value = commitments->value;

        if (commitments->content & COMMITMENTS_BLINDING_KEY) {
            JADE_STATIC_ASSERT(sizeof(outinfo->blinding_key) == sizeof(commitments->blinding_key));
            memcpy(outinfo->blinding_key, commitments->blinding_key, sizeof(commitments->blinding_key));
            outinfo->flags |= OUTPUT_FLAG_HAS_BLINDING_KEY;
        }
    } else if (txoutput->asset[0] != WALLY_TX_ASSET_CT_EXPLICIT_PREFIX
        || txoutput->value[0] != WALLY_TX_ASSET_CT_EXPLICIT_PREFIX) {
        // No blinding info for blinded output - may not be an issue if we're
        // not interested in this output.  Just set flags appropriately.
        outinfo->flags |= OUTPUT_FLAG_CONFIDENTIAL;

        // NOTE: This is not valid if this output has been validated as belonging to this wallet
        if (outinfo->flags & OUTPUT_FLAG_VALIDATED) {
            *errmsg = "Missing blinding information for wallet output";
            return false;
        }
    } else {
        // unconfidential, take directly from the tx
        outinfo->flags |= OUTPUT_FLAG_HAS_UNBLINDED;

        // Copy the asset ID without the leading unconfidential tag byte
        // NOTE: we reverse the asset-id bytes to the 'display' order
        reverse(outinfo->asset_id, txoutput->asset + 1, sizeof(outinfo->asset_id));

        JADE_WALLY_VERIFY(
            wally_tx_confidential_value_to_satoshi(txoutput->value, txoutput->value_len, &outinfo->value));
    }

    return true;
}

bool validate_elements_outputs(jade_process_t* process, const network_t network_id, const struct wally_tx* tx,
    const TxType_t txtype, commitment_t* commitments, output_info_t* output_info, asset_summary_t* in_sums,
    const size_t num_in_sums, asset_summary_t* out_sums, const size_t num_out_sums, uint64_t* fees)
{
    JADE_ASSERT(tx);
    JADE_ASSERT(commitments);
    JADE_ASSERT(output_info);
    JADE_ASSERT(fees);

    const char* errmsg = NULL;
    *fees = 0;

    uint8_t policy_asset[ASSET_TAG_LEN];
    network_to_policy_asset(network_id, policy_asset, sizeof(policy_asset));

    // Check the trusted commitments: expect one element in the array for each output.
    // Can be null for unblinded outputs as we will skip them.
    // Populate an `output_index` -> (blinding_key, asset, value) map

    // NOTE: some advanced tx types permit some outputs to be blind (ie blinded, without unblinding info/proofs)
    // By default/in the basic 'send payment' case all outputs must have unconfidential/unblinded.
    const bool allow_blind_outputs = txtype == TXTYPE_SWAP; // swaps allow 'other wallets' blind outputs

    // Save fees for the final confirmation screen
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        // Gather the (unblinded) output info for user confirmation
        output_info_t* outinfo = output_info + i;
        if (!add_output_info(&commitments[i], &tx->outputs[i], outinfo, &errmsg)) {
            goto done;
        }

        // If are not allowing blinded outputs, check each confidential output has unblinding info
        if (!allow_blind_outputs && outinfo->flags & OUTPUT_FLAG_CONFIDENTIAL) {
            if (!(outinfo->flags & OUTPUT_FLAG_HAS_UNBLINDED) || !(outinfo->flags & OUTPUT_FLAG_HAS_BLINDING_KEY)) {
                errmsg = "Missing commitments data for blinded output";
                goto done;
            }
        }

        // Collect fees (ie. outputs with no script)
        // NOTE: fees must be unconfidential, and must be denominated in the policy asset
        if (!tx->outputs[i].script) {
            if (outinfo->flags & OUTPUT_FLAG_CONFIDENTIAL) {
                errmsg = "Fee output (without script) cannot be blinded";
                goto done;
            }
            if (memcmp(outinfo->asset_id, policy_asset, sizeof(policy_asset))) {
                errmsg = "Unexpected fee output (without script) asset-id";
                goto done;
            }
            if (!outinfo->value) {
                errmsg = "Fee output (without script) cannot be 0";
                goto done;
            }
            if (*fees) {
                errmsg = "Unexpected multiple fee outputs (without script)";
                goto done;
            }
            *fees += outinfo->value;
        }

        // If the output has been verified as belonging to this wallet, we can
        // use it to validate some part of any passed input- or output- summary.
        if (outinfo->flags & OUTPUT_FLAG_VALIDATED) {
            JADE_ASSERT(outinfo->flags & OUTPUT_FLAG_HAS_UNBLINDED);

            if (outinfo->flags & OUTPUT_FLAG_CHANGE) {
                // NOTE: change outputs are subtracted from the relevant 'input summary'.
                asset_summary_update(
                    in_sums, num_in_sums, outinfo->asset_id, sizeof(outinfo->asset_id), (0 - outinfo->value));
            } else {
                asset_summary_update(
                    out_sums, num_out_sums, outinfo->asset_id, sizeof(outinfo->asset_id), outinfo->value);
            }
        }
    }
done:
    if (errmsg) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        return false;
    }
    return true;
}

bool show_elements_fee_confirmation_activity(const network_t network_id, const struct wally_tx* tx,
    const output_info_t* outinfo, const script_flavour_t aggregate_inputs_scripts_flavour, const uint64_t fees,
    const TxType_t txtype, const bool is_partial)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(tx);
    JADE_ASSERT(outinfo);

    const char* const warning_msg
        = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED ? WARN_MSG_MIXED_INPUTS : NULL;
    const char* title = (txtype == TXTYPE_SWAP) ? (is_partial ? "Swap Proposal" : "Complete Swap") : "Send Transaction";

    // Return whether the user accepts or declines
    return show_elements_final_confirmation_activity(network_id, title, fees, warning_msg);
}
#endif // AMALGAMATED_BUILD
