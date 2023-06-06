#include "../gui.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/address.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "../button_events.h"

#include <esp_event.h>
#include <wally_script.h>

#include "process_utils.h"

bool show_confirm_address_activity(const char* address, bool default_selection);

void get_receive_address_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_receive_address");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);
    const bool isLiquid = isLiquidNetwork(network);

    // Handle single-sig and generic multisig script variants
    // (Green-multisig is the default for backwards compatibility)
    size_t script_len = 0;
    uint8_t script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient for all scripts

    char warning_msg[128];
    warning_msg[0] = '\0';
    const char* errmsg = NULL;

    uint8_t multisig_master_blinding_key[HMAC_SHA512_LEN];
    const uint8_t* p_master_blinding_key = NULL;
    size_t master_blinding_key_len = 0;

    bool confidential = isLiquid; // default to confidential addresses for liquid
    rpc_get_boolean("confidential", &params, &confidential);
    if (confidential && !isLiquid) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Confidential addresses only apply to liquid networks", NULL);
        goto cleanup;
    }

    if (rpc_has_field_data("multisig_name", &params)) {
        // Load multisig data record
        multisig_data_t multisig_data;
        char multisig_name[MAX_MULTISIG_NAME_SIZE];
        if (!params_load_multisig(&params, multisig_name, sizeof(multisig_name), &multisig_data, &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }

        // Get the paths (suffixes) and derive pubkeys
        const bool is_change = false;
        uint8_t pubkeys[MAX_MULTISIG_SIGNERS * EC_PUBLIC_KEY_LEN]; // Sufficient
        if (!params_multisig_pubkeys(is_change, &params, &multisig_data, pubkeys, sizeof(pubkeys), &written,
                warning_msg, sizeof(warning_msg), &errmsg)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
            goto cleanup;
        }

        // Build a script pubkey for the passed parameters
        if (!wallet_build_multisig_script(multisig_data.variant, multisig_data.sorted, multisig_data.threshold, pubkeys,
                written, script, sizeof(script), &script_len)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid multisig script", NULL);
            goto cleanup;
        }

        if (confidential) {
            if (!multisig_get_master_blinding_key(
                    &multisig_data, multisig_master_blinding_key, sizeof(multisig_master_blinding_key), &errmsg)) {
                jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
                goto cleanup;
            }
            p_master_blinding_key = multisig_master_blinding_key;
            master_blinding_key_len = sizeof(multisig_master_blinding_key);
        }
    } else {
        uint32_t path[MAX_PATH_LEN];
        size_t path_len = 0;
        const size_t max_path_len = sizeof(path) / sizeof(path[0]);

        char variant[MAX_VARIANT_LEN];
        script_variant_t script_variant;

        // Green-multisig is the default (for backwards compatibility) if no variant passed
        written = 0;
        rpc_get_string("variant", sizeof(variant), &params, variant, &written);
        if (!get_script_variant(variant, written, &script_variant)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid script variant parameter", NULL);
            goto cleanup;
        }

        if (is_greenaddress(script_variant)) {
            // For green-multisig the path is constructed from subaccount, branch and pointer
            size_t subaccount = 0, branch = 0, pointer = 0;
            if (!rpc_get_sizet("subaccount", &params, &subaccount) || !rpc_get_sizet("branch", &params, &branch)
                || !rpc_get_sizet("pointer", &params, &pointer)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract path elements from parameters", NULL);
                goto cleanup;
            }
            wallet_build_receive_path(subaccount, branch, pointer, path, max_path_len, &path_len);

            // Optional xpub for 2of3 accounts
            written = 0;
            char xpubrecovery[120]; // Should be sufficient as all xpubs should be <= 112
            rpc_get_string("recovery_xpub", sizeof(xpubrecovery), &params, xpubrecovery, &written);

            // Optional 'blocks' for csv outputs
            size_t csvBlocks = 0;
            rpc_get_sizet("csv_blocks", &params, &csvBlocks);

            if (csvBlocks && !csvBlocksExpectedForNetwork(network, csvBlocks)) {
                const int ret
                    = snprintf(warning_msg, sizeof(warning_msg), "Warning:\nNon-standard csv:\n%u", csvBlocks);
                JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg));
            }

            // Build a script pubkey for the passed parameters
            if (!wallet_build_ga_script(network, written ? xpubrecovery : NULL, csvBlocks, path, path_len, script,
                    sizeof(script), &script_len)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid green address script", NULL);
                goto cleanup;
            }
        } else if (is_singlesig(script_variant)) {
            // For single-sig the path is explicit in the params
            rpc_get_bip32_path("path", &params, path, max_path_len, &path_len);
            if (path_len == 0) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters", NULL);
                goto cleanup;
            }

            // If paths not as expected show a warning message with the address
            bool is_change = false;
            if (!wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len)) {
                is_change = true;
                is_change = wallet_is_expected_singlesig_path(network, script_variant, is_change, path, path_len);

                char path_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
                if (!wallet_bip32_path_as_str(path, path_len, path_str, sizeof(path_str))) {
                    jade_process_reject_message(
                        process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format", NULL);
                    goto cleanup;
                }
                const char* path_desc = is_change ? "Note:\nChange path" : "Warning:\nUnusual path";
                const int ret = snprintf(warning_msg, sizeof(warning_msg), "%s\n%s", path_desc, path_str);
                JADE_ASSERT(ret > 0 && ret < sizeof(warning_msg));
            }

            // Build a script pubkey for the passed parameters
            struct ext_key derived;
            if (!wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &derived)
                || !wallet_build_singlesig_script(
                    script_variant, derived.pub_key, sizeof(derived.pub_key), script, sizeof(script), &script_len)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to generate valid singlesig script", NULL);
                goto cleanup;
            }
        } else {
            // Multisig handled above, so should be nothing left
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unhandled script variant", NULL);
            goto cleanup;
        }

        if (confidential) {
            // Standard
            p_master_blinding_key = keychain_get()->master_unblinding_key;
            master_blinding_key_len = sizeof(keychain_get()->master_unblinding_key);
        }
    }

    // Convert that into an address string
    JADE_ASSERT(script_len > 0);
    char address[MAX_ADDRESS_LEN];
    if (isLiquid) {
        if (confidential) {
            // Blind address
            JADE_ASSERT(p_master_blinding_key && master_blinding_key_len == HMAC_SHA512_LEN);
            uint8_t blinding_key[EC_PUBLIC_KEY_LEN];
            if (!wallet_get_public_blinding_key(p_master_blinding_key, master_blinding_key_len, script, script_len,
                    blinding_key, sizeof(blinding_key))) {
                jade_process_reject_message(
                    process, CBOR_RPC_INTERNAL_ERROR, "Cannot get blinding key for script", NULL);
                goto cleanup;
            }
            elements_script_to_address(
                network, script, script_len, blinding_key, sizeof(blinding_key), address, sizeof(address));
        } else {
            JADE_ASSERT(!p_master_blinding_key && !master_blinding_key_len);
            elements_script_to_address(network, script, script_len, NULL, 0, address, sizeof(address));
        }
    } else {
        JADE_ASSERT(!confidential && !p_master_blinding_key && !master_blinding_key_len);
        script_to_address(network, script, script_len, address, sizeof(address));
    }

    // Display to the user to confirm
    const bool default_selection = false;
    if (!show_confirm_address_activity(address, default_selection)) {
        JADE_LOGW("User declined to confirm address");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to confirm address", NULL);
        goto cleanup;
    }

    JADE_LOGD("User pressed accept");

    // Show warning if necessary
    if (warning_msg[0] != '\0') {
        await_message_activity(warning_msg);
    }

    // Reply with the address
    jade_process_reply_to_message_result(process->ctx, address, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
