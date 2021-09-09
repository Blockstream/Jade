#include "../button_events.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"

#include <sodium/utils.h>

#include "process_utils.h"

// Wallet initialisation functions
void initialise_with_mnemonic(bool temporary_restore);
void get_passphrase(char* passphrase, size_t passphrase_len, bool confirm);

// Pinserver interaction
bool pinclient_get(
    jade_process_t* process, const uint8_t* pin, const size_t pin_size, uint8_t* finalaes, const size_t finalaes_len);
bool pinclient_set(
    jade_process_t* process, const uint8_t* pin, const size_t pin_size, uint8_t* finalaes, const size_t finalaes_len);

void check_pin_load_keys(jade_process_t* process)
{
    // At this point we should have encrypted keys persisted in the flash but
    // *NOT* have any keys in-memory.  We need the pinserver data to decrypt.
    JADE_ASSERT(!keychain_get());
    JADE_ASSERT(keychain_has_pin());

    const uint8_t pin_attempts_remaining = keychain_pin_attempts_remaining();
    JADE_ASSERT(pin_attempts_remaining > 0); // Shouldn't be here otherwise
    JADE_LOGD("pin attempts remaining: %u", pin_attempts_remaining);

    const char* msg = NULL;
    switch (pin_attempts_remaining) {
    case 2:
        msg = "\nEnter PIN:\n(Two attempts remaining)";
        break;
    case 1:
        msg = "\nEnter PIN:\n(Final attempt)";
        break;
    default:
        msg = "\nEnter PIN:";
    }
    JADE_ASSERT(msg);

    pin_insert_activity_t* pin_insert;
    make_pin_insert_activity(&pin_insert, "Unlock Jade", msg);
    JADE_ASSERT(pin_insert);
    jade_process_free_on_exit(process, pin_insert);
    SENSITIVE_PUSH(pin_insert, sizeof(pin_insert_activity_t));

    gui_set_current_activity(pin_insert->activity);

// In a debug unattended ci build, use hardcoded pin after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    run_pin_entry_loop(pin_insert);
    uint8_t pin[sizeof(pin_insert->pin)];
    memcpy(pin, pin_insert->pin, sizeof(pin));
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    uint8_t pin[] = { 0, 1, 2, 3, 4, 5 };
#endif
    SENSITIVE_PUSH(pin, sizeof(pin));
    display_message_activity("Checking...");

    // Ok, have keychain and a PIN - do the pinserver 'getpin' process
    unsigned char aeskey[AES_KEY_LEN_256];
    SENSITIVE_PUSH(aeskey, sizeof(aeskey));
    if (!pinclient_get(process, pin, sizeof(pin), aeskey, sizeof(aeskey))) {
        // Server or networking/connection error
        // NOTE: reply message will have already been sent
        goto cleanup;
    }

    // Load wallet master key from flash
    if (!keychain_load_cleartext(aeskey, sizeof(aeskey))) {
        JADE_LOGE("Failed to load keys - Incorrect PIN");
        jade_process_reply_to_message_fail(process);
        await_error_activity("Incorrect PIN!");
        goto cleanup;
    }

    // See if we additionally need a passphrase from the user
    if (keychain_requires_passphrase()) {
        // Loading from storage succeeded, but we still have no wallet keys.
        // - Requires the input of a user passphrase also.
        char passphrase[PASSPHRASE_MAX_LEN + 1];
        const bool confirm_passphrase = false;
        get_passphrase(passphrase, sizeof(passphrase), confirm_passphrase);

        display_message_activity("Processing...");

        if (!keychain_complete_derivation_with_passphrase(passphrase)) {
            JADE_LOGE("Failed to derive wallet using passphrase");
            jade_process_reject_message(
                process, CBOR_RPC_INTERNAL_ERROR, "Failed to store key data encrypted in flash memory", NULL);
            goto cleanup;
        }
    }

    // Re-set the (loaded) keychain in order to confirm the 'source'
    // (ie interface) which we will accept receiving messages from.
    // (This also clears any temporarily cached mnemonic entropy data)
    keychain_set(keychain_get(), process->ctx.source, false);

    // All good
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    // Clear out pin and temporary keychain
    SENSITIVE_POP(aeskey);
    SENSITIVE_POP(pin);
    SENSITIVE_POP(pin_insert);
}

static void set_pin_save_keys(jade_process_t* process)
{
    // At this point we should have keys in-memory, but should *NOT* have
    // any encrypted keys persisted in the flash memory - ie. no PIN set.
    JADE_ASSERT(keychain_get());
    JADE_ASSERT(!keychain_has_pin());
    JADE_ASSERT(!keychain_has_temporary());

    // Enter PIN to lock mnemonic/key material.
    // In a debug unattended ci build, use hardcoded pin after a short delay
    pin_insert_activity_t* pin_insert;
    make_pin_insert_activity(&pin_insert, "Enter New PIN", "\nNew PIN:");
    JADE_ASSERT(pin_insert);
    jade_process_free_on_exit(process, pin_insert);
    SENSITIVE_PUSH(pin_insert, sizeof(pin_insert_activity_t));

    uint8_t pin[sizeof(pin_insert->pin)];
    SENSITIVE_PUSH(pin, sizeof(pin));

    while (true) {
        gui_set_title("Enter New PIN");
        gui_set_current_activity(pin_insert->activity);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        run_pin_entry_loop(pin_insert);
#else
        const uint8_t testpin[sizeof(pin_insert->pin)] = { 0, 1, 2, 3, 4, 5 };

        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        memcpy(pin_insert->pin, testpin, sizeof(testpin));
#endif

        // this is the first pin, copy it and clear screen fields
        memcpy(pin, pin_insert->pin, sizeof(pin));
        clear_current_pin(pin_insert);

        // have user confirm it
        gui_set_title("Confirm New PIN");
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        run_pin_entry_loop(pin_insert);
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        memcpy(pin_insert->pin, testpin, sizeof(testpin));
#endif

        // check that the two pins are the same
        JADE_LOGD("Checking pins match");
        if (!sodium_memcmp(pin, pin_insert->pin, sizeof(pin))) {
            // Pins match
            JADE_LOGI("New pin confirmed");
            break;
        } else {
            // Pins mismatch - try again
            await_error_activity("Pin mismatch, please try again");
            clear_current_pin(pin_insert);
        }
    }

    display_message_activity("Persisting PIN data...");

    // Ok, have keychain and a PIN - do the pinserver 'setpin' process
    unsigned char aeskey[AES_KEY_LEN_256];
    SENSITIVE_PUSH(aeskey, sizeof(aeskey));
    if (!pinclient_set(process, pin, sizeof(pin), aeskey, sizeof(aeskey))) {
        // Server or networking/connection error
        // NOTE: reply message will have already been sent
        goto cleanup;
    }

    // Persist wallet master key (or mnemonic entropy if passphrase-protected) to flash memory
    if (!keychain_store_encrypted(aeskey, sizeof(aeskey))) {
        JADE_LOGE("Failed to store key data encrypted in flash memory!");
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to store key data encrypted in flash memory", NULL);
        await_error_activity("Failed to persist key data");
        goto cleanup;
    }

    // Re-set the (same) keychain in order to confirm the 'source'
    // (ie interface) which we will accept receiving messages from.
    // (This also clears any temporarily cached mnemonic entropy data)
    keychain_set(keychain_get(), process->ctx.source, false);

    // All good
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    // Clear out pin and temporary keychain
    SENSITIVE_POP(aeskey);
    SENSITIVE_POP(pin);
    SENSITIVE_POP(pin_insert);
}

void auth_user_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];
    size_t written = 0;

    ASSERT_CURRENT_MESSAGE(process, "auth_user");
    GET_MSG_PARAMS(process);

    rpc_get_string("network", sizeof(network), &params, network, &written);
    if (written == 0 || !isValidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid network from parameters", NULL);
        goto cleanup;
    }

    CHECK_NETWORK_CONSISTENT(process, network, written);

    // We have five cases:
    // 1. Temporary - has a temporary keys in memory
    //    - nothing to do here, just return ok  (having checked message source)
    // 2. Ready - has persisted/encrypted keys, and these have been decrypted and are ready to use
    //    - nothing to do here, just return ok  (having checked message source)
    // 3. Locked - has persisted/encrypted keys, but no keys in memory
    //    - needs pin entry to unlock - prompt for pin
    // 4. Unsaved-keys - has no persisted/encrypted keys but does have unsaved keys in memory
    //    - prompt for PIN to secure/encrypt the keys
    // 5. Uninitialised - has no persisted/encrypted keys and no keys in memory
    //    - prompt for mnemonic setup, then onto PIN to secure keys

    if (keychain_has_temporary()) {
        JADE_LOGI("using temporary keychain already present - skipping PIN step");
        JADE_ASSERT(keychain_get());

        if (KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)) {
            JADE_LOGI("temporary keychain already unlocked by this message-source");
            jade_process_reply_to_message_ok(process);
        } else if (keychain_get_userdata() == SOURCE_NONE) {
            // First use of this temporary wallet
            // Re-set the (same) keychain in order to confirm the 'source'
            // (ie interface) which we will accept receiving messages from.
            JADE_LOGI("First use of temporary keychain, associating with this message-source");
            keychain_set(keychain_get(), process->ctx.source, true);
            jade_process_reply_to_message_ok(process);
        } else {
            // Reject the message as hw locked
            JADE_LOGI("Trying to reuse temporary keychain with different message-source");
            jade_process_reject_message(process, CBOR_RPC_HW_LOCKED,
                "Cannot process message - temporary wallet associated with different connection", NULL);
        }
    } else if (keychain_has_pin()) {
        // Jade is initialised with persisted wallet - if required use PIN to unlock
        if (KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)) {
            JADE_LOGI("keychain already unlocked by this message-source");
            jade_process_reply_to_message_ok(process);
        } else {
            JADE_LOGI("keychain locked for this source, requesting pin");
            keychain_free();
            check_pin_load_keys(process);
        }
    } else {
        // Jade hw is not fully initialised - if we have an 'in-memory' mnemonic
        // then offer to persist that (with PIN and key derived with the pinserver)
        if (!keychain_get()) {
            // No (in-memory) mnemonic has been set, offer to do that now
            // (This is not ideal as can take a long time and host app is
            // waiting for a message reply and may time out.)
            JADE_LOGI("no wallet data, requesting mnemonic");
            initialise_with_mnemonic(false);
        }

        if (!keychain_get()) {
            // No mnemonic entered, fail
            jade_process_reply_to_message_fail(process);
            goto cleanup;
        }

        JADE_LOGI("requesting new pin");
        set_pin_save_keys(process);
    }

#ifndef CONFIG_DEBUG_MODE
    // If not a debug build, we restrict the hw to this network type
    // (In case it wasn't set at wallet creation/recovery time [older fw])
    keychain_set_network_type_restriction(network);
#endif
    JADE_LOGI("Success");

cleanup:
    return;
}
