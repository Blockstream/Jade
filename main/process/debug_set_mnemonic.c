#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../qrscan.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include <cbor.h>

#include "process_utils.h"

#define LONGEST_WORD 9
#define NUM_OF_WORDS 24
#define NULLSTRING 1
#define MAX_MNEMONIC_LEN (LONGEST_WORD * NUM_OF_WORDS + NULLSTRING)

// Function to interpret scanned qr code string.
// Called in this code to test it separately from camera or qr interpretation.
bool import_and_validate_mnemonic(qr_data_t* qr_data);

#ifdef CONFIG_DEBUG_MODE
void debug_set_mnemonic_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "debug_set_mnemonic");

    GET_MSG_PARAMS(process);

    qr_data_t qr_data = { .len = 0, .is_valid = import_and_validate_mnemonic };
    SENSITIVE_PUSH(&qr_data, sizeof(qr_data));
    char passphrase[PASSPHRASE_MAX_LEN + 1];
    SENSITIVE_PUSH(passphrase, sizeof(passphrase));
    const char* p_passphrase = NULL;
    bool temporary_wallet = false;
    const uint8_t* seed = NULL;
    size_t written = 0;

    keychain_t keydata = { 0 };
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // Get field which can be set to test 'temporary restore' wallet
    rpc_get_boolean("temporary_wallet", &params, &temporary_wallet);

    // Slightly hacky, can accept a seed or a mnemonic
    if (rpc_has_field_data("seed", &params)) {
        rpc_get_bytes_ptr("seed", &params, &seed, &written);
        if (written != 32 && written != 64) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid seed from parameters", NULL);
            goto cleanup;
        }
        keychain_derive_from_seed(seed, written, &keydata);

        // A 'seed' wallet is implicitly always a 'temporary' wallet
        // (as we have no mnemonic entropy to persist)
        temporary_wallet = true;
    } else {
        // Extract the mnemonic data from the message into the qr_data structure
        // (ie. as if we had just scanned this string from a qr code)
        // If fetching as a string fails, try fetching as bytes
        rpc_get_string("mnemonic", sizeof(qr_data.data), &params, (char*)qr_data.data, &qr_data.len);
        if (qr_data.len == 0) {
            rpc_get_bytes("mnemonic", sizeof(qr_data.data), &params, qr_data.data, &qr_data.len);
        }
        if (qr_data.len == 0) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract mnemonic prefixes from parameters", NULL);
            goto cleanup;
        }

        // Here we call into the code used when scanning a qr code, as this facilitates testing
        // the various supported formats separately from qr recognition/interpretation.
        // NOTE: only the English wordlist is supported.
        if (!import_and_validate_mnemonic(&qr_data)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to expand mnemonic prefixes into full mnemonic words", NULL);
            goto cleanup;
        }

        // Any bip39 passphrase
        if (rpc_has_field_data("passphrase", &params)) {
            written = 0;
            rpc_get_string("passphrase", sizeof(passphrase), &params, passphrase, &written);
            if (written == 0 || written > PASSPHRASE_MAX_LEN) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid passphrase from parameters", NULL);
                goto cleanup;
            }
            p_passphrase = passphrase;
        }

        // Derive a keychain from the passed mnemonic and passphrase
        if (!keychain_derive_from_mnemonic((const char*)qr_data.data, p_passphrase, &keydata)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to derive keychain from mnemonic", NULL);
            goto cleanup;
        }
    }

    // Pop up a notification that the wallet has been injected
    // (In a 'real' scenario the wallet is not set without some gui activity)
    const char* message[] = { "Warning: debug wallet" };
    await_message_activity(message, 1);
    vTaskDelay(250 / portTICK_PERIOD_MS);

    // Copy temporary keychain into a new global keychain
    // and remove the restriction on network-types.
    keychain_set(&keydata, (uint8_t)process->ctx.source, temporary_wallet);
    keychain_clear_network_type_restriction();
    keychain_set_confirm_export_blinding_key(true);

    // To be consistent with normal wallet setup in mnemonic.c ...
    if (!temporary_wallet) {
        JADE_ASSERT(!seed);

        // We need to cache the root mnemonic entropy as it is this that we will persist
        // encrypted to local flash (requiring a passphrase to derive the wallet master key).
        keychain_cache_mnemonic_entropy((const char*)qr_data.data);
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(passphrase);
    SENSITIVE_POP(&qr_data);
    return;
}
#endif // CONFIG_DEBUG_MODE
#endif // AMALGAMATED_BUILD
