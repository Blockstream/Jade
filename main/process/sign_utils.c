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

bool params_txn_validate(const network_t network_id, const bool for_liquid, const struct wally_tx* const tx,
    uint64_t* explicit_fee, const char** errmsg)
{
    JADE_ASSERT(tx);
    JADE_ASSERT(explicit_fee);
    JADE_INIT_OUT_PPTR(errmsg);

    size_t is_elements = 0;
    JADE_WALLY_VERIFY(wally_tx_is_elements(tx, &is_elements));
    if (for_liquid != is_elements) {
        *errmsg = "Transaction is the wrong type for the current network";
        return false;
    }

    if (!for_liquid) {
        return true; // Bitcoin: No further checks needed
    }

    // Liquid checks
    uint8_t policy_asset[ASSET_TAG_LEN];
    network_to_policy_asset(network_id, policy_asset, sizeof(policy_asset));
    reverse_in_place(policy_asset, sizeof(policy_asset));

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        const struct wally_tx_output* const txout = tx->outputs + i;
        JADE_ASSERT(txout->asset && txout->asset_len == WALLY_TX_ASSET_CT_LEN);
        JADE_ASSERT(txout->value && txout->value_len);
        const uint8_t explicit_prefix = WALLY_TX_ASSET_CT_EXPLICIT_PREFIX;
        const bool is_explicit_asset = txout->asset[0] == explicit_prefix;
        const bool is_explicit_value = txout->value[0] == explicit_prefix;

        if (is_explicit_asset != is_explicit_value) {
            *errmsg = "Output asset and value blinding inconsistent";
            return false;
        }
        if (is_explicit_value) {
            JADE_ASSERT(txout->value_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
        } else {
            JADE_ASSERT(txout->value_len == WALLY_TX_ASSET_CT_VALUE_LEN);
        }

        if (tx->outputs[i].script) {
            continue; // Not a fee output, no further checks needed
        }

        // Fee output
        if (!is_explicit_asset || !is_explicit_value) {
            *errmsg = "Fee output (without script) cannot be blinded";
            return false;
        }
        if (*explicit_fee) {
            *errmsg = "Unexpected multiple fee outputs (without script)";
            return false;
        }
        JADE_WALLY_VERIFY(wally_tx_confidential_value_to_satoshi(txout->value, txout->value_len, explicit_fee));
        if (!*explicit_fee) {
            *errmsg = "Fee output (without script) cannot be 0";
            return false;
        }
        // Note we compare the asset id ignoring the initial explicit byte
        if (memcmp(txout->asset + 1, policy_asset, sizeof(policy_asset))) {
            *errmsg = "Unexpected fee output (without script) asset-id";
            return false;
        }
    }

    return true;
}

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

#ifdef CONFIG_SPIRAM
// Workaround to run 'wally_explicit_surjectionproof_verify()' and 'wally_explicit_rangeproof_verify()'
// on a temporary stack, as the underlying libsecp calls require over 50kb of stack space.
// NOTE: devices without SPIRAM do not have sufficient free memory to be able to do this verification,
// so atm we exclude it for those devices.
static bool verify_explicit_proofs(void* ctx)
{
    JADE_ASSERT(ctx);

    const ext_commitment_t* ec = (const ext_commitment_t*)ctx;
    const commitment_t* c = &ec->c;
    JADE_ASSERT(c->content & (COMMITMENTS_ASSET_BLIND_PROOF | COMMITMENTS_VALUE_BLIND_PROOF));

    if (c->content & COMMITMENTS_ASSET_BLIND_PROOF) {
        uint8_t reversed_asset_id[sizeof(c->asset_id)];
        reverse(reversed_asset_id, c->asset_id, sizeof(c->asset_id));

        // NOTE: Appears to require ~52kb of stack space
        if (wally_explicit_surjectionproof_verify(ec->asset_blind_proof, sizeof(ec->asset_blind_proof),
                reversed_asset_id, sizeof(reversed_asset_id), ec->asset_generator, sizeof(ec->asset_generator))
            != WALLY_OK) {
            // Failed to verify explicit asset proof
            return false;
        }
    }

    if (c->content & COMMITMENTS_VALUE_BLIND_PROOF) {
        // NOTE: Appears to require ~40kb of stack space
        if (wally_explicit_rangeproof_verify(ec->value_blind_proof, ec->value_blind_proof_len, c->value,
                ec->value_commitment, sizeof(ec->value_commitment), ec->asset_generator, sizeof(ec->asset_generator))
            != WALLY_OK) {
            // Failed to verify explicit value proof
            return false;
        }
    }

    return true;
}
#endif // CONFIG_SPIRAM

bool params_commitment_data(
    CborValue* item, commitment_t* commitment, const struct wally_tx_output* const txout, const char** errmsg)
{
    JADE_ASSERT(item);
    JADE_ASSERT(commitment);
    // txout is optional
    JADE_INIT_OUT_PPTR(errmsg);

    commitment->content = COMMITMENTS_NONE;

    ext_commitment_t ec;
    ec.c.content = COMMITMENTS_NONE;

    // Need abf or asset_blind_proof
    if (rpc_get_n_bytes("abf", item, sizeof(ec.c.abf), ec.c.abf)) {
        ec.c.content |= COMMITMENTS_ABF;
    }

    if (rpc_get_n_bytes("asset_blind_proof", item, sizeof(ec.asset_blind_proof), ec.asset_blind_proof)) {
        ec.c.content |= COMMITMENTS_ASSET_BLIND_PROOF;
    }

    if (!(ec.c.content & (COMMITMENTS_ABF | COMMITMENTS_ASSET_BLIND_PROOF))) {
        // No commitment data present
        return false;
    }

    // Need vbf or value_blind_proof
    if (rpc_get_n_bytes("vbf", item, sizeof(ec.c.vbf), ec.c.vbf)) {
        ec.c.content |= COMMITMENTS_VBF;
    }

    size_t written = 0;
    rpc_get_bytes("value_blind_proof", sizeof(ec.value_blind_proof), item, ec.value_blind_proof, &written);
    if (written && written <= sizeof(ec.value_blind_proof)) {
        ec.value_blind_proof_len = (uint8_t)written; // Sufficient
        ec.c.content |= COMMITMENTS_VALUE_BLIND_PROOF;
    }

    if (!(ec.c.content & (COMMITMENTS_VBF | COMMITMENTS_VALUE_BLIND_PROOF))
        || !rpc_get_n_bytes("asset_id", item, sizeof(ec.c.asset_id), ec.c.asset_id)
        || !rpc_get_uint64_t("value", item, &ec.c.value)) {
        *errmsg = "Invalid or missing trusted commitment data";
        return false;
    }

    // Blinding key is optional in some scenarios
    if (rpc_get_n_bytes("blinding_key", item, sizeof(ec.c.blinding_key), ec.c.blinding_key)) {
        ec.c.content |= COMMITMENTS_BLINDING_KEY;
    }

    // For tx output commitments:
    // - Actual commitments are optional - but must be both commitments or neither.
    // - If passed, these must match values in the tx output.
    // - If not passed, the values from the tx output are used instead.
    // For tx input commitments (i.e. 'txout' parameter is NULL):
    // - Actual commitments are mandatory
    //
    // The above blinding factors/proofs are then verified against the commitments.
    const bool have_asset_generator
        = rpc_get_n_bytes("asset_generator", item, sizeof(ec.asset_generator), ec.asset_generator);
    const bool have_value_commitment
        = rpc_get_n_bytes("value_commitment", item, sizeof(ec.value_commitment), ec.value_commitment);
    const bool are_commitments_consistent = have_asset_generator == have_value_commitment;

    if (!are_commitments_consistent || (!txout && !have_asset_generator)) {
        // Either inconsistently provided, or not provided for a tx input
        *errmsg = "Invalid or missing trusted commitment data";
        return false;
    }
    if (txout) {
        if (txout->asset_len != sizeof(ec.asset_generator)
            || (have_asset_generator && memcmp(txout->asset, ec.asset_generator, sizeof(ec.asset_generator)))) {
            *errmsg = "Failed to verify trusted commitment data with tx";
            return false;
        }
        if (txout->value_len != sizeof(ec.value_commitment)) {
            *errmsg = "Failed to verify trusted commitment data with tx";
            return false;
        }
        if (have_asset_generator) {
            // Ensure the commitments match the output values
            if (memcmp(txout->asset, ec.asset_generator, sizeof(ec.asset_generator))
                || memcmp(txout->value, ec.value_commitment, sizeof(ec.value_commitment))) {
                *errmsg = "Failed to verify trusted commitment data with tx";
                return false;
            }
        } else {
            // Copy the commitments from the tx output for validation
            memcpy(ec.asset_generator, txout->asset, sizeof(ec.asset_generator));
            memcpy(ec.value_commitment, txout->value, sizeof(ec.value_commitment));
        }
    }

    // 1. Asset generator
    // If passed the abf, check the blinded asset commitment can be reconstructed
    // (ie. from the given reversed asset_id and abf)
    if (ec.c.content & COMMITMENTS_ABF) {
        uint8_t reversed_asset_id[sizeof(ec.c.asset_id)];
        reverse(reversed_asset_id, ec.c.asset_id, sizeof(ec.c.asset_id));

        uint8_t cmp[sizeof(ec.asset_generator)];
        if (wally_asset_generator_from_bytes(
                reversed_asset_id, sizeof(reversed_asset_id), ec.c.abf, sizeof(ec.c.abf), cmp, sizeof(cmp))
                != WALLY_OK
            || sodium_memcmp(ec.asset_generator, cmp, sizeof(cmp)) != 0) {
            *errmsg = "Failed to verify trusted commitment data with tx";
            return false;
        }
    }

    // 2. Value commitment
    // If passed the vbf, check the blinded value commitment can be reconstructed
    // (ie. from the given value, asset_generator and vbf)
    if (ec.c.content & COMMITMENTS_VBF) {
        uint8_t cmp[sizeof(ec.value_commitment)];
        if (wally_asset_value_commitment(ec.c.value, ec.c.vbf, sizeof(ec.c.vbf), ec.asset_generator,
                sizeof(ec.asset_generator), cmp, sizeof(cmp))
                != WALLY_OK
            || sodium_memcmp(ec.value_commitment, cmp, sizeof(cmp)) != 0) {
            *errmsg = "Failed to verify trusted commitment data with tx";
            return false;
        }
    }

    // Verify any blinded proofs
    // NOTE: only a device with SPIRAM has sufficient memory to be able to do this verification.
    if (ec.c.content & (COMMITMENTS_ASSET_BLIND_PROOF | COMMITMENTS_VALUE_BLIND_PROOF)) {
#ifdef CONFIG_SPIRAM
        // Because the libsecp calls 'secp256k1_surjectionproof_verify()' and 'secp256k1_rangeproof_verify()'
        // requires more stack space than is available to the main task, we run that function in a temporary task.
        const size_t stack_size = 54 * 1024; // 54kb seems sufficient
        if (!run_in_temporary_task(stack_size, verify_explicit_proofs, (void*)&ec)) {
            *errmsg = "Failed to verify explicit asset/value commitment proofs";
            return false;
        }
#else
        *errmsg = "Devices without external SPIRAM are unable to verify explicit proofs";
        return false;
#endif // CONFIG_SPIRAM
    }
    // Copy out the valid commitment data for the caller
    memcpy(commitment, &ec.c, sizeof(ec.c));
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
    size_t num_outputs = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_outputs);
    if (cberr != CborNoError || !num_outputs || num_outputs != tx->num_outputs) {
        errmsg = "Unexpected number of trusted commitments for transaction";
        goto cleanup;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        errmsg = "Invalid trusted commitments for transaction";
        goto cleanup;
    }

    commitment_t* const commitments = JADE_CALLOC(num_outputs, sizeof(commitment_t));
    jade_process_free_on_exit(process, commitments);

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        commitments[i].content = COMMITMENTS_NONE;

        if (cbor_value_is_null(&arrayItem)) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!cbor_value_is_map(&arrayItem)) {
            errmsg = "Invalid or missing trusted commitment data";
            goto cleanup;
        }

        size_t num_map_items = 0;
        if (cbor_value_get_map_length(&arrayItem, &num_map_items) == CborNoError && num_map_items == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        // Populate commitments data for the tx output if present
        params_commitment_data(&arrayItem, &commitments[i], &tx->outputs[i], &errmsg);
        if (errmsg) {
            goto cleanup;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr == CborNoError) {
        *data = commitments;
    } else {
        errmsg = "Invalid or missing trusted commitment data";
    }

cleanup:
    if (errmsg) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        return false;
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
    JADE_STATIC_ASSERT(sizeof(outinfo->asset_id) == sizeof(commitments->asset_id));
    JADE_STATIC_ASSERT(sizeof(outinfo->blinding_key) == sizeof(commitments->blinding_key));

    JADE_ASSERT(!(outinfo->flags & (OUTPUT_FLAG_CONFIDENTIAL | OUTPUT_FLAG_HAS_UNBLINDED)));
    if (commitments->content != COMMITMENTS_NONE) {
        // Output to be confidential/blinded, use the commitments data
        outinfo->flags |= (OUTPUT_FLAG_CONFIDENTIAL | OUTPUT_FLAG_HAS_UNBLINDED);

        // Fetch the asset_id, value, and optional blinding_key into the info struct
        memcpy(outinfo->asset_id, commitments->asset_id, sizeof(commitments->asset_id));
        outinfo->value = commitments->value;

        if (commitments->content & COMMITMENTS_BLINDING_KEY) {
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
    const size_t num_in_sums, asset_summary_t* out_sums, const size_t num_out_sums)
{
    JADE_ASSERT(tx);
    JADE_ASSERT(commitments);
    JADE_ASSERT(output_info);

    const char* errmsg = NULL;

    uint8_t policy_asset[ASSET_TAG_LEN];
    network_to_policy_asset(network_id, policy_asset, sizeof(policy_asset));

    // Check the trusted commitments: expect one element in the array for each output.
    // Can be null for unblinded outputs as we will skip them.
    // Populate an `output_index` -> (blinding_key, asset, value) map

    // NOTE: some advanced tx types permit some outputs to be blind (ie blinded, without unblinding info/proofs)
    // By default/in the basic 'send payment' case all outputs must have unconfidential/unblinded.
    const bool allow_blind_outputs = txtype == TXTYPE_SWAP; // swaps allow 'other wallets' blind outputs

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        // Gather the (unblinded) output info for user confirmation
        output_info_t* outinfo = output_info + i;
        if (!add_output_info(&commitments[i], &tx->outputs[i], outinfo, &errmsg)) {
            goto done;
        }

        // If are not allowing blinded outputs, check each confidential output has unblinding info
        if (!allow_blind_outputs && outinfo->flags & OUTPUT_FLAG_CONFIDENTIAL) {
            if (!(outinfo->flags & OUTPUT_FLAG_HAS_UNBLINDED) || !(outinfo->flags & OUTPUT_FLAG_HAS_BLINDING_KEY)) {
                errmsg = "Missing trusted commitment data for blinded output";
                goto done;
            }
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

bool sighash_is_supported(const TxType_t txtype, const uint32_t sig_type, const uint32_t sighash, const bool for_liquid,
    const bool is_partial)
{
    if (for_liquid && txtype == TXTYPE_SWAP && is_partial) {
        // Liquid partial swap: must be SINGLE | ACP
        return sighash == (WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY);
    }
    if (sig_type == WALLY_SIGTYPE_SW_V1) {
        // Taproot: must be ALL or DEFAULT
        return sighash == WALLY_SIGHASH_DEFAULT || sighash == WALLY_SIGHASH_ALL;
    }
    // All other cases must be ALL at present
    return sighash == WALLY_SIGHASH_ALL;
}

bool show_btc_fee_confirmation_activity(const network_t network_id, const struct wally_tx* tx,
    const output_info_t* outinfo, const script_flavour_t aggregate_inputs_scripts_flavour, const uint64_t input_amount,
    const uint64_t output_amount)
{
    JADE_ASSERT(tx);
    // outputinfo is optional
    JADE_ASSERT(input_amount);
    JADE_ASSERT(output_amount);

    JADE_ASSERT(input_amount >= output_amount);

    // User to agree fee amount
    // The fee amount is the shortfall between input and output amounts
    // The 'spend' amount is the total of the outputs not flagged as change
    const uint64_t fees = input_amount - output_amount;
    uint64_t spend_amount = output_amount;
    if (outinfo) {
        for (size_t i = 0; i < tx->num_outputs; ++i) {
            if (outinfo[i].flags & OUTPUT_FLAG_CHANGE) {
                // Deduct change output amount
                JADE_ASSERT(spend_amount >= tx->outputs[i].satoshi);
                spend_amount -= tx->outputs[i].satoshi;
            }
        }
    }

    char warnbuf[128]; // sufficient
    const char* warning_msg = NULL;
    const bool warn_fees = fees && fees >= spend_amount;
    const bool warn_scripts = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED;
    if (warn_fees && warn_scripts) {
        const int retval = snprintf(warnbuf, sizeof(warnbuf), "%s %s", WARN_MSG_HIGH_FEES, WARN_MSG_MIXED_INPUTS);
        JADE_ASSERT(retval > 0 && retval < sizeof(warnbuf));
        warning_msg = warnbuf;
    } else if (warn_scripts) {
        warning_msg = WARN_MSG_MIXED_INPUTS;
    } else if (warn_fees) {
        warning_msg = WARN_MSG_HIGH_FEES;
    }

    // Return whether the user accepts or declines
    return show_btc_final_confirmation_activity(network_id, fees, warning_msg);
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
