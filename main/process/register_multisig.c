#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "process_utils.h"

#include <ctype.h>
#include <sodium/utils.h>

void make_confirm_multisig_activity(const char* multisig_name, bool sorted, size_t threshold, const signer_t* signers,
    size_t num_signers, const uint8_t* wallet_fingerprint, size_t wallet_fingerprint_len, bool overwriting,
    gui_activity_t** first_activity);

static bool multisig_name_valid(const char* name)
{
    // Allow ascii 33-126 incl - ie. letters, numbers and other printable/punctuation characters
    // NOTE: space and \n are not allowed.
    for (const char* pch = name; *pch != '\0'; ++pch) {
        if (!isgraph(*pch)) {
            return false;
        }
    }
    return true;
}

void register_multisig_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];
    char multisig_name[MAX_MULTISIG_NAME_SIZE];
    char variant[MAX_VARIANT_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_multisig");
    GET_MSG_PARAMS(process);

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);

    if (isLiquidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Multisig is not supported for liquid networks", NULL);
        goto cleanup;
    }

    // Get name of multisig wallet
    written = 0;
    rpc_get_string("multisig_name", sizeof(multisig_name), &params, multisig_name, &written);
    if (written == 0 || !multisig_name_valid(multisig_name)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Missing or invalid multisig name parameter", NULL);
        goto cleanup;
    }

    CborValue descriptor;
    if (!rpc_get_map("descriptor", &params, &descriptor)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract multisig descriptor data", NULL);
        goto cleanup;
    }

    // Handle script variants.
    written = 0;
    script_variant_t script_variant;
    rpc_get_string("variant", sizeof(variant), &descriptor, variant, &written);
    if (!get_script_variant(variant, written, &script_variant) || !is_multisig(script_variant)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid script variant parameter", NULL);
        goto cleanup;
    }

    // Handle sorted-multisig - defaults to false if not passed
    bool sorted = false;
    if (rpc_has_field_data("sorted", &descriptor)) {
        if (!rpc_get_boolean("sorted", &descriptor, &sorted)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid sorted flag value", NULL);
            goto cleanup;
        }
    }

    // Threshold
    written = 0;
    rpc_get_sizet("threshold", &descriptor, &written);
    if (written == 0 || written > MAX_MULTISIG_SIGNERS) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid multisig threshold value", NULL);
        goto cleanup;
    }
    const uint8_t threshold = (uint8_t)written;

    // Co-Signers
    signer_t* signers = NULL;
    size_t num_signers = 0;
    rpc_get_signers_allocate("signers", &descriptor, &signers, &num_signers);
    if (num_signers == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid co-signers from parameters", NULL);
        goto cleanup;
    }
    jade_process_free_on_exit(process, signers);

    if (num_signers > MAX_MULTISIG_SIGNERS) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid co-signers from parameters", NULL);
        goto cleanup;
    }

    if (threshold > num_signers) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Invalid multisig threshold for number of co-signers", NULL);
        goto cleanup;
    }

    // Validate signers
    uint8_t wallet_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(wallet_fingerprint, sizeof(wallet_fingerprint));
    if (!multisig_validate_signers(network, signers, num_signers, wallet_fingerprint, sizeof(wallet_fingerprint))) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to validate multisig co-signers", NULL);
        goto cleanup;
    }

    // Serialise as bytes
    uint8_t registration[MULTISIG_BYTES_LEN(MAX_MULTISIG_SIGNERS)]; // Sufficient
    const size_t registration_len = MULTISIG_BYTES_LEN(num_signers);
    JADE_ASSERT(registration_len <= sizeof(registration));
    if (!multisig_data_to_bytes(
            script_variant, sorted, threshold, signers, num_signers, registration, registration_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to serialise multisig registration", NULL);
        goto cleanup;
    }

    // See if a record for this name exists already
    const bool overwriting = storage_multisig_name_exists(multisig_name);

    // If so, see if it is identical to the record we are trying to persist
    // - if so, just return true immediately.
    if (overwriting) {
        written = 0;
        uint8_t existing[MULTISIG_BYTES_LEN(MAX_MULTISIG_SIGNERS)]; // Sufficient
        if (storage_get_multisig_registration(multisig_name, existing, sizeof(existing), &written)
            && written == registration_len && !sodium_memcmp(existing, registration, registration_len)) {
            JADE_LOGI("Multisig %s: identical registration exists, returning immediately", multisig_name);
            goto return_ok;
        }
    } else {
        // Not overwriting an existing record - check storage slot available
        if (storage_get_multisig_registration_count() >= MAX_MULTISIG_REGISTRATIONS) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Already have maximum number of multisig wallets", NULL);
            goto cleanup;
        }
    }

    gui_activity_t* first_activity = NULL;
    make_confirm_multisig_activity(multisig_name, sorted, threshold, signers, num_signers, wallet_fingerprint,
        sizeof(wallet_fingerprint), overwriting, &first_activity);
    JADE_ASSERT(first_activity);
    gui_set_current_activity(first_activity);

    // ----------------------------------
    // wait for the last "next" (proceed with the protocol and then final confirmation)
    int32_t ev_id;
    // In a debug unattended ci build, assume buttons pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const esp_err_t gui_ret = sync_await_single_event(JADE_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const esp_err_t gui_ret = ESP_OK;
    ev_id = MULTISIG_ACCEPT;
#endif

    // Check to see whether user accepted or declined
    if (gui_ret != ESP_OK || ev_id != MULTISIG_ACCEPT) {
        JADE_LOGW("User declined to register multisig");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to register multisig", NULL);
        goto cleanup;
    }

    JADE_LOGD("User accepted multisig");

    // Persist multisig registration in nvs
    if (!storage_set_multisig_registration(multisig_name, registration, registration_len)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to persist multisig registration", NULL);
        goto cleanup;
    }

return_ok:
    // Ok, all verified and persisted
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
