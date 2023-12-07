#include "../descriptor.h"
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

void get_child_key_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "dervice_child");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

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

if (rpc_has_field_data("dervice_child", &params) {
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
            if (!wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PRIVATE, &derived)) {
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
    jade_process_reply_to_message_result(process->ctx, derived, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
