#include "../assets.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../utils/temporary_stack.h"
#include "../utils/util.h"
#include "../wallet.h"

#include <sodium/utils.h>
#include <wally_anti_exfil.h>
#include <wally_elements.h>

#include "process_utils.h"

bool show_elements_transaction_outputs_activity(const char* network, const struct wally_tx* tx,
    const output_info_t* output_info, const asset_info_t* assets, size_t num_assets);
bool show_elements_swap_activity(const char* network, bool initial_proposal,
    const movement_summary_info_t* wallet_input_summary, size_t wallet_input_summary_size,
    const movement_summary_info_t* wallet_output_summary, size_t wallet_output_summary_size, const asset_info_t* assets,
    size_t num_assets);
bool show_elements_final_confirmation_activity(
    const char* network, const char* title, const uint64_t fee, const char* warning_msg);

// From sign_tx.c
bool validate_wallet_outputs(jade_process_t* process, const char* network, const struct wally_tx* tx,
    CborValue* wallet_outputs, output_info_t* output_info, const char** errmsg);
void send_ae_signature_replies(jade_process_t* process, signing_data_t* all_signing_data, uint32_t num_inputs);
void send_ec_signature_replies(jade_msg_source_t source, signing_data_t* all_signing_data, uint32_t num_inputs);

static void wally_free_tx_wrapper(void* tx) { JADE_WALLY_VERIFY(wally_tx_free((struct wally_tx*)tx)); }

static const char TX_TYPE_STR_SWAP[] = "swap";
static const char TX_TYPE_STR_SEND_PAYMENT[] = "send_payment";
typedef enum { TXTYPE_UNKNOWN, TXTYPE_SEND_PAYMENT, TXTYPE_SWAP } TxType_t;

// Map a txtype string to an enum value
#define TX_TYPE_STR_MATCH(typestr) ((len == sizeof(typestr) - 1 && !strncmp(type, typestr, sizeof(typestr) - 1)))
static TxType_t get_txtype(const char* type, const size_t len)
{
    if (type && len) {
        if (TX_TYPE_STR_MATCH(TX_TYPE_STR_SWAP)) {
            return TXTYPE_SWAP;
        }
        if (TX_TYPE_STR_MATCH(TX_TYPE_STR_SEND_PAYMENT)) {
            return TXTYPE_SEND_PAYMENT;
        }
    }
    return TXTYPE_UNKNOWN;
}

static void get_wallet_summary_allocate(
    const char* field, const CborValue* value, movement_summary_info_t** data, size_t* written)
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

    movement_summary_info_t* const summary = JADE_CALLOC(num_array_items, sizeof(movement_summary_info_t));

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        movement_summary_info_t* const item = summary + i;

        if (cbor_value_is_null(&arrayItem) || !cbor_value_is_map(&arrayItem)) {
            free(summary);
            return;
        }

        if (!rpc_get_n_bytes("asset_id", &arrayItem, sizeof(item->asset_id), item->asset_id)) {
            free(summary);
            return;
        }

        if (!rpc_get_uint64_t("satoshi", &arrayItem, &item->value)) {
            free(summary);
            return;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(summary);
        return;
    }

    *written = num_array_items;
    *data = summary;
}

static TxType_t get_additional_info_allocate(const char* field, CborValue* params, bool* is_partial,
    movement_summary_info_t** wallet_input_summary, size_t* wallet_input_summary_size,
    movement_summary_info_t** wallet_output_summary, size_t* wallet_output_summary_size)
{
    JADE_ASSERT(field);
    JADE_ASSERT(params);
    JADE_ASSERT(is_partial);
    JADE_INIT_OUT_PPTR(wallet_input_summary);
    JADE_INIT_OUT_SIZE(wallet_input_summary_size);
    JADE_INIT_OUT_PPTR(wallet_output_summary);
    JADE_INIT_OUT_SIZE(wallet_output_summary_size);

    // If no 'additional_data' passed, assume this is a a simple send-payment 'classic' tx
    CborValue additional_info;
    if (!rpc_get_map(field, params, &additional_info)) {
        return TXTYPE_SEND_PAYMENT;
    }

    // input/output summaries required for some complex txn types, eg. swaps
    get_wallet_summary_allocate(
        "wallet_input_summary", &additional_info, wallet_input_summary, wallet_input_summary_size);
    get_wallet_summary_allocate(
        "wallet_output_summary", &additional_info, wallet_output_summary, wallet_output_summary_size);

    // 'partial' flag (defaults to false)
    if (!rpc_get_boolean("is_partial", &additional_info, is_partial)) {
        *is_partial = false;
    }

    // Tx Type
    const char* ptype = NULL;
    size_t typelen = 0;
    rpc_get_string_ptr("tx_type", &additional_info, &ptype, &typelen);
    return get_txtype(ptype, typelen);
}

static bool validate_summary_asset_amount(movement_summary_info_t* summary, const size_t summary_size,
    const uint8_t* asset_id, const size_t asset_id_len, const uint64_t value)
{
    JADE_ASSERT(summary);
    JADE_ASSERT(asset_id);
    JADE_ASSERT(asset_id_len == sizeof(summary->asset_id));

    // Add passed sats amount to the first record found with matching asset_id
    for (size_t i = 0; i < summary_size; ++i) {
        if (!memcmp(asset_id, summary[i].asset_id, sizeof(summary[i].asset_id))) {
            summary[i].validated_value += value;
            return true;
        }
    }
    return false;
}

static bool check_summary_validated(movement_summary_info_t* summary, const size_t summary_size)
{
    JADE_ASSERT(summary);

    // Check every asset record has been fully validated
    for (size_t i = 0; i < summary_size; ++i) {
        if (summary[i].value != summary[i].validated_value) {
            char* asset_id_hex = NULL;
            wally_hex_from_bytes(summary[i].asset_id, sizeof(summary[i].asset_id), &asset_id_hex);
            JADE_LOGW("Failed to validate input/output summary for %s", asset_id_hex);
            JADE_WALLY_VERIFY(wally_free_string(asset_id_hex));
            return false;
        }
    }
    return true;
}

static bool get_commitment_data(CborValue* item, commitment_t* commitment)
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

static void get_commitments_allocate(const char* field, const CborValue* value, commitment_t** data, size_t* written)
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

    commitment_t* const commitments = JADE_CALLOC(num_array_items, sizeof(commitment_t));

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        commitments[i].content = COMMITMENTS_NONE;

        if (cbor_value_is_null(&arrayItem)) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!cbor_value_is_map(&arrayItem)) {
            free(commitments);
            return;
        }

        size_t num_map_items = 0;
        if (cbor_value_get_map_length(&arrayItem, &num_map_items) == CborNoError && num_map_items == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        // Populate commitments data
        if (!get_commitment_data(&arrayItem, &commitments[i])) {
            free(commitments);
            return;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(commitments);
        return;
    }

    *written = num_array_items;
    *data = commitments;
}

#ifdef CONFIG_ESP32_SPIRAM_SUPPORT
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
#endif // CONFIG_ESP32_SPIRAM_SUPPORT || !CONFIG_BT_ENABLED

static bool verify_commitment_consistent(const commitment_t* commitments, const char** errmsg)
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
#ifdef CONFIG_ESP32_SPIRAM_SUPPORT
        // Because the libsecp calls 'secp256k1_surjectionproof_verify()' and 'secp256k1_rangeproof_verify()'
        // requires more stack space than is available to the main task, we run that function with a temporary stack.
        const size_t stack_size = 54 * 1024; // 54kb seems sufficient
        if (!run_on_temporary_stack(stack_size, verify_explicit_proofs, (void*)commitments)) {
            *errmsg = "Failed to verify explicit asset/value commitment proofs";
            return false;
        }
#else
        *errmsg = "Devices without external SPIRAM are unable to verify explicit proofs";
        return false;
#endif // CONFIG_ESP32_SPIRAM_SUPPORT || !CONFIG_BT_ENABLED
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
        JADE_ASSERT(sizeof(outinfo->asset_id) == sizeof(commitments->asset_id));
        memcpy(outinfo->asset_id, commitments->asset_id, sizeof(commitments->asset_id));
        outinfo->value = commitments->value;

        if (commitments->content & COMMITMENTS_BLINDING_KEY) {
            JADE_ASSERT(sizeof(outinfo->blinding_key) == sizeof(commitments->blinding_key));
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

/*
 * The message flow here is complicated because we cater for both a legacy flow
 * for standard deterministic EC signatures (see rfc6979) and a newer message
 * exchange added later to cater for anti-exfil signatures.
 * At the moment we retain the older message flow for backward compatibility,
 * but at some point we should remove it and use the new message flow for all
 * cases, which would simplify the code here and in the client.
 */
void sign_liquid_tx_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;
    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_liquid_tx");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const jade_msg_source_t source = process->ctx.source;

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);
    if (!isLiquidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "sign_liquid_tx call only appropriate for liquid network", NULL);
        goto cleanup;
    }

    written = 0;
    const uint8_t* txbytes = NULL;
    rpc_get_bytes_ptr("txn", &params, &txbytes, &written);

    if (written == 0) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract txn from parameters", NULL);
        goto cleanup;
    }
    JADE_ASSERT(txbytes);

    struct wally_tx* tx = NULL;
    const int res = wally_tx_from_bytes(txbytes, written, WALLY_TX_FLAG_USE_ELEMENTS, &tx); // elements, without witness
    if (res != WALLY_OK || !tx) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract tx from passed bytes", NULL);
        goto cleanup;
    }
    jade_process_call_on_exit(process, wally_free_tx_wrapper, tx);

    // copy the amount
    size_t num_inputs = 0;
    bool ret = rpc_get_sizet("num_inputs", &params, &num_inputs);
    if (!ret || num_inputs == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid number of inputs from parameters", NULL);
        goto cleanup;
    }

    // Check the number of inputs the client wants to send is what we
    // would expect for the given transaction.  Fail if not.
    if (num_inputs != tx->num_inputs) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Unexpected number of inputs for transaction", NULL);
        goto cleanup;
    }

    // Copy trusted commitment data into a temporary structure (so we can free the message)
    commitment_t* commitments = NULL;
    size_t num_commitments = 0;
    get_commitments_allocate("trusted_commitments", &params, &commitments, &num_commitments);

    if (num_commitments == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract trusted commitments from parameters", NULL);
        goto cleanup;
    }

    JADE_ASSERT(commitments);
    jade_process_free_on_exit(process, commitments);

    // Check the trusted commitments: expect one element in the array for each output.
    // (Can be null/zero's for unblinded outputs.)
    if (num_commitments != tx->num_outputs) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Unexpected number of trusted commitments for transaction", NULL);
        goto cleanup;
    }

    // We always need this extra data to 'unblind' confidential txns
    output_info_t* output_info = JADE_CALLOC(tx->num_outputs, sizeof(output_info_t));
    jade_process_free_on_exit(process, output_info);

    // Whether to use Anti-Exfil signatures and message flow
    // Optional flag, defaults to false
    bool use_ae_signatures = false;
    rpc_get_boolean("use_ae_signatures", &params, &use_ae_signatures);

    // Can optionally be passed info for wallet outputs, which we verify internally
    // NOTE: Element named 'change' for backward-compatibility reasons
    const char* errmsg = NULL;
    if (rpc_has_field_data("change", &params)) {
        CborValue wallet_outputs;
        if (rpc_get_array("change", &params, &wallet_outputs)) {
            if (!validate_wallet_outputs(process, network, tx, &wallet_outputs, output_info, &errmsg)) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
                goto cleanup;
            }
        }
    }

    // Can optionally be passed asset info data (registry json)
    // NOTE: these asset-info structs point at fields in the current message
    // IE. THIS DATA IS NOT VALID AFTER THE INITIAL MESSAGE HAS BEEN PROCESSED
    asset_info_t* assets = NULL;
    size_t num_assets = 0;
    if (!assets_get_allocate("asset_info", &params, &assets, &num_assets)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid asset info passed", NULL);
        goto cleanup;
    }
    jade_process_free_on_exit(process, assets);
    JADE_LOGI("Read %d assets from message", num_assets);

    // Get any data from the option 'additional_info' section
    movement_summary_info_t* wallet_input_summary = NULL;
    size_t wallet_input_summary_size = 0;
    movement_summary_info_t* wallet_output_summary = NULL;
    size_t wallet_output_summary_size = 0;
    bool tx_is_partial = false;
    const TxType_t txtype = get_additional_info_allocate("additional_info", &params, &tx_is_partial,
        &wallet_input_summary, &wallet_input_summary_size, &wallet_output_summary, &wallet_output_summary_size);
    jade_process_free_on_exit(process, wallet_input_summary);
    jade_process_free_on_exit(process, wallet_output_summary);

    // Shouldn't have pointers to empty arrays
    JADE_ASSERT(!wallet_input_summary == !wallet_input_summary_size);
    JADE_ASSERT(!wallet_output_summary == !wallet_output_summary_size);

    // Validate tx type data
    if (txtype == TXTYPE_SWAP) {
        // Input and output summary must be present - they will be fully validated later
        if (!wallet_input_summary || !wallet_output_summary) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Swap tx missing input/output summary information", NULL);
            goto cleanup;
        }

        // Validate swap or proposal appears to have expected inputs and outputs
        if (tx_is_partial) {
            // At this time the only 'partial swap' we accept is an initial proposal with exactly one
            // input and exactly one output which is to self, and in a different asset to the input
            if (tx->num_inputs != 1 || tx->num_outputs != 1 || wallet_input_summary_size != 1
                || wallet_output_summary_size != 1
                || !memcmp(wallet_input_summary->asset_id, wallet_output_summary->asset_id,
                    sizeof(wallet_output_summary->asset_id))) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS,
                    "Initial swap proposal must have single wallet input and output in different assets", NULL);
                goto cleanup;
            }
        } else {
            // TODO: Ideally check total number of assets in our inputs and outputs
            if (tx->num_inputs < 2 || tx->num_outputs < 2) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Insufficient inputs/outputs for a swap tx", NULL);
                goto cleanup;
            }
        }
    } else if (txtype != TXTYPE_SEND_PAYMENT) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unsupported tx-type in additional info", NULL);
        goto cleanup;
    }

    // Check the trusted commitments: expect one element in the array for each output.
    // Can be null for unblinded outputs as we will skip them.
    // Populate an `output_index` -> (blinding_key, asset, value) map
    uint8_t policy_asset[ASSET_TAG_LEN];
    const char* policy_asset_hex = networkGetPolicyAsset(network);
    JADE_WALLY_VERIFY(wally_hex_to_bytes(policy_asset_hex, policy_asset, sizeof(policy_asset), &written));
    JADE_ASSERT(written == sizeof(policy_asset));

    // NOTE: some advanced tx types permit some outputs to be blind (ie blinded, without unblinding info/proofs)
    // By default/in the basic 'send payment' case all outputs must have unconfidential/unblinded.
    const bool allow_blind_outputs = txtype == TXTYPE_SWAP; // swaps allow 'other wallets' blind outputs

    // Save fees for the final confirmation screen
    uint64_t fees = 0;
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        if ((tx->outputs[i].asset[0] == WALLY_TX_ASSET_CT_EXPLICIT_PREFIX)
            != (tx->outputs[i].value[0] == WALLY_TX_ASSET_CT_EXPLICIT_PREFIX)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Output asset and value blinding inconsistent", NULL);
            goto cleanup;
        }

        // Gather the (unblinded) output info for user confirmation
        const char* errmsg = NULL;
        if (!add_output_info(&commitments[i], &tx->outputs[i], &output_info[i], &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }

        // If are not allowing blinded outputs, check each confidential output has unblinding info
        if (!allow_blind_outputs && output_info[i].flags & OUTPUT_FLAG_CONFIDENTIAL) {
            if (!(output_info[i].flags & OUTPUT_FLAG_HAS_UNBLINDED)
                || !(output_info[i].flags & OUTPUT_FLAG_HAS_BLINDING_KEY)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Missing commitments data for blinded output", NULL);
                goto cleanup;
            }
        }

        // Collect fees (ie. outputs with no script)
        // NOTE: fees must be unconfidential, and must be denominated in the policy asset
        if (!tx->outputs[i].script) {
            if (output_info[i].flags & OUTPUT_FLAG_CONFIDENTIAL) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Fee output (without script) cannot be blinded", NULL);
                goto cleanup;
            }
            if (memcmp(output_info[i].asset_id, policy_asset, sizeof(policy_asset))) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Unexpected fee output (without script) asset-id", NULL);
                goto cleanup;
            }
            fees += output_info[i].value;
        }

        // If the output has been verified as belonging to this wallet, we can
        // use it to validate some part of any passed input- or output- summary.
        if (output_info[i].flags & OUTPUT_FLAG_VALIDATED) {
            JADE_ASSERT(output_info[i].flags & OUTPUT_FLAG_HAS_UNBLINDED);

            // NOTE: change outputs are subtracted from the relevant 'input summary'.
            if (wallet_input_summary && (output_info[i].flags & OUTPUT_FLAG_CHANGE)) {
                validate_summary_asset_amount(wallet_input_summary, wallet_input_summary_size, output_info[i].asset_id,
                    sizeof(output_info[i].asset_id), (0 - output_info[i].value));
            } else if (wallet_output_summary) {
                validate_summary_asset_amount(wallet_output_summary, wallet_output_summary_size,
                    output_info[i].asset_id, sizeof(output_info[i].asset_id), output_info[i].value);
            }
        }
    }

    if (txtype == TXTYPE_SWAP) {
        // Confirm wallet-summary info (ie. net inputs and outputs)
        if (!show_elements_swap_activity(network, tx_is_partial, wallet_input_summary, wallet_input_summary_size,
                wallet_output_summary, wallet_output_summary_size, assets, num_assets)) {
            JADE_LOGW("User declined to sign swap transaction");
            jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
            goto cleanup;
        }
    } else {
        // Confirm all non-change outputs
        if (!show_elements_transaction_outputs_activity(network, tx, output_info, assets, num_assets)) {
            JADE_LOGW("User declined to sign transaction");
            jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
            goto cleanup;
        }
    }

    JADE_LOGD("User accepted outputs");
    display_processing_message_activity();

    // Send ok - client should send inputs
    jade_process_reply_to_message_ok(process);

    // We generate the hashes for each input but defer signing them
    // until after the final user confirmation.  Hold them in an block for
    // ease of cleanup if something goes wrong part-way through.
    signing_data_t* const all_signing_data = JADE_CALLOC(num_inputs, sizeof(signing_data_t));
    jade_process_free_on_exit(process, all_signing_data);

    // We track if the type of the inputs we are signing changes (ie. single-sig vs
    // green/multisig/other) so we can show a warning to the user if so.
    script_flavour_t aggregate_inputs_scripts_flavour = SCRIPT_FLAVOUR_NONE;

    // Run through each input message and generate a signature-hash for each one
    // NOTE: atm we only usually accept 'SIGHASH_ALL' for inputs we are signing - the exception
    // being an initial swap proposal when we expect WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY
    const uint8_t expected_sighash = (txtype == TXTYPE_SWAP && tx_is_partial)
        ? (WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY)
        : WALLY_SIGHASH_ALL;
    for (size_t index = 0; index < num_inputs; ++index) {
        jade_process_load_in_message(process, true);
        if (!IS_CURRENT_MESSAGE(process, "tx_input")) {
            // Protocol error
            jade_process_reject_message(
                process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'tx_input'", NULL);
            goto cleanup;
        }

        // txn input as expected - get input parameters
        GET_MSG_PARAMS(process);

        bool is_witness = false;
        size_t script_len = 0;
        const uint8_t* script = NULL;

        // The ae commitments for this input (if using anti-exfil signatures)
        size_t ae_host_commitment_len = 0;
        const uint8_t* ae_host_commitment = NULL;
        uint8_t ae_signer_commitment[WALLY_S2C_OPENING_LEN];

        // Make and store the reply data, and then delete the (potentially
        // large) input message.  Replies will be sent after user confirmation.
        written = 0;
        signing_data_t* const sig_data = all_signing_data + index;
        rpc_get_id(&process->ctx.value, sig_data->id, sizeof(sig_data->id), &written);
        JADE_ASSERT(written != 0);

        // Path node can be omitted if we don't want to sign this input
        // (But if passed must be valid - empty/root path is not allowed for signing)
        // Make signature-hash (should have a prevout script in hand)
        const bool has_path = rpc_has_field_data("path", &params);
        if (has_path) {
            // Get all common tx-signing input fields which must be present if a path is given
            if (!params_tx_input_signing_data(use_ae_signatures, &params, &is_witness, sig_data, &ae_host_commitment,
                    &ae_host_commitment_len, &script, &script_len, &aggregate_inputs_scripts_flavour, &errmsg)) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
                goto cleanup;
            }

            // NOTE: Check the sighash is as expected
            if (sig_data->sighash != expected_sighash) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unsupported sighash value", NULL);
                goto cleanup;
            }

            // As we are signing this input, use it to validate some part of any passed 'input summary'
            if (wallet_input_summary) {
                // We can only verify input amounts with segwit inputs which have an explicit commitment to sign
                if (!is_witness) {
                    jade_process_reject_message(
                        process, CBOR_RPC_BAD_PARAMETERS, "Non-segwit input cannot be used as verified amount", NULL);
                    goto cleanup;
                }

                // Verify any blinding info for this input - note can only use blinded inputs
                commitment_t commitment;
                if (get_commitment_data(&params, &commitment)) {
                    if (!verify_commitment_consistent(&commitment, &errmsg)) {
                        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
                        goto cleanup;
                    }
                    validate_summary_asset_amount(wallet_input_summary, wallet_input_summary_size, commitment.asset_id,
                        sizeof(commitment.asset_id), commitment.value);
                }
            }

            size_t value_len = 0;
            const uint8_t* value_commitment = NULL;
            if (is_witness) {
                JADE_LOGD("For segwit input using explicitly passed value_commitment");
                rpc_get_bytes_ptr("value_commitment", &params, &value_commitment, &value_len);
                if (value_len != ASSET_COMMITMENT_LEN && value_len != WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN) {
                    jade_process_reject_message(
                        process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract value commitment from parameters", NULL);
                    goto cleanup;
                }
            }

            // Generate hash of this input which we will sign later
            if (!wallet_get_elements_tx_input_hash(tx, index, is_witness, script, script_len,
                    value_len == 0 ? NULL : value_commitment, value_len, sig_data->sighash, sig_data->signature_hash,
                    sizeof(sig_data->signature_hash))) {
                jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to make tx input hash", NULL);
                goto cleanup;
            }

            // If using anti-exfil signatures, compute signer commitment for returning to caller
            if (use_ae_signatures) {
                JADE_ASSERT(ae_host_commitment);
                JADE_ASSERT(ae_host_commitment_len == WALLY_HOST_COMMITMENT_LEN);
                if (!wallet_get_signer_commitment(sig_data->signature_hash, sizeof(sig_data->signature_hash),
                        sig_data->path, sig_data->path_len, ae_host_commitment, ae_host_commitment_len,
                        ae_signer_commitment, sizeof(ae_signer_commitment))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to make ae signer commitment", NULL);
                    goto cleanup;
                }
            }
        } else {
            // Empty byte-string reply (no path given implies no sig needed or expected)
            JADE_ASSERT(!script);
            JADE_ASSERT(script_len == 0);
            JADE_ASSERT(sig_data->path_len == 0);
        }

        // If using ae-signatures, reply with the signer commitment
        // FIXME: change message flow to reply here even when not using ae-signatures
        // as this simplifies the code both here and in the client.
        if (use_ae_signatures) {
            uint8_t buffer[256];
            jade_process_reply_to_message_bytes(process->ctx, ae_signer_commitment,
                has_path ? sizeof(ae_signer_commitment) : 0, buffer, sizeof(buffer));
        }
    }

    // Check the summary information for each asset as previously confirmed
    // by the user is consistent with the verified input and outputs.
    if (wallet_input_summary && wallet_output_summary) {
        if (!check_summary_validated(wallet_input_summary, wallet_input_summary_size)
            || !check_summary_validated(wallet_output_summary, wallet_output_summary_size)) {
            JADE_LOGW("Failed to fully validate input and output summary information");
            // If using ae-signatures, we need to load the message to send the error back on
            if (use_ae_signatures) {
                jade_process_load_in_message(process, true);
            }
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to validate input/output summary information", NULL);
            goto cleanup;
        }
        JADE_LOGI("Input and output summary information validated");
    }

    if (tx_is_partial && !fees) {
        // Partial tx without fees - can skip the fee screen ?
        JADE_LOGI("No fees for partial tx, so skipping fee confirmation screen");
    } else {
        const char* const warning_msg
            = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED ? WARN_MSG_MIXED_INPUTS : NULL;
        const char* title
            = (txtype == TXTYPE_SWAP) ? (tx_is_partial ? "Swap Proposal" : "Complete Swap") : "Send Transaction";

        // If user cancels we'll send the 'cancelled' error response for the last input message only
        if (!show_elements_final_confirmation_activity(network, title, fees, warning_msg)) {
            // If using ae-signatures, we need to load the message to send the error back on
            if (use_ae_signatures) {
                jade_process_load_in_message(process, true);
            }
            JADE_LOGW("User declined to sign transaction");
            jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign transaction", NULL);
            goto cleanup;
        }

        JADE_LOGD("User accepted fee");
    }
    display_processing_message_activity();

    // Send signature replies.
    // NOTE: currently we have two message flows - the backward compatible version
    // for normal EC signatures, and the new flow required for Anti-Exfil signatures.
    // Once we have migrated the companion applications onto AE signatures we should
    // convert normal EC signatures to use the new/improved message flow.
    if (use_ae_signatures) {
        // Generate and send Anti-Exfil signature replies
        send_ae_signature_replies(process, all_signing_data, num_inputs);
    } else {
        // Generate and send standard EC signature replies
        send_ec_signature_replies(source, all_signing_data, num_inputs);
    }
    JADE_LOGI("Success");

cleanup:
    return;
}
