#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../power.h"
#include "../process.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"

#include <sodium/utils.h>

#include "process_utils.h"

// Wallet initialisation functions
void initialise_with_mnemonic(bool temporary_restore, bool force_qr_scan, bool* offer_qr_temporary);
void get_passphrase(char* passphrase, size_t passphrase_len);

// Pinserver interaction
bool pinclient_get(
    jade_process_t* process, const uint8_t* pin, const size_t pin_len, uint8_t* finalaes, const size_t finalaes_len);
bool pinclient_set(
    jade_process_t* process, const uint8_t* pin, const size_t pin_len, uint8_t* finalaes, const size_t finalaes_len);

// Whether we want to change the PIN on the next unlock
static bool change_pin_requested = false;

void set_request_change_pin(const bool change_pin) { change_pin_requested = change_pin; }

static void check_wallet_erase_pin(jade_process_t* process, const uint8_t* pin_entered, const size_t pin_len)
{
    JADE_ASSERT(pin_entered);

    uint8_t pin_erase[PIN_SIZE];
    if (pin_len == sizeof(pin_erase) && storage_get_wallet_erase_pin(pin_erase, sizeof(pin_erase))
        && !sodium_memcmp(pin_erase, pin_entered, pin_len)) {
        // 'Wallet erase' PIN entered.  Erase wallet keys and reset passphrase setting
        keychain_erase_encrypted();
        keychain_set_passphrase_frequency(PASSPHRASE_NEVER);
        keychain_persist_key_flags();

        // Show/return 'Internal Error' message, and shut-down
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Internal Error", NULL);

        const char* message[] = { "Internal Error!" };
        await_error_activity(message, 1);
        power_shutdown();
    }
}

static bool get_pin_get_aeskey(jade_process_t* process, const char* title, uint8_t* pin, const size_t pin_len,
    uint8_t* aeskey, const size_t aes_len)
{
    JADE_ASSERT(process);
    JADE_ASSERT(title);
    JADE_ASSERT(pin);
    JADE_ASSERT(pin_len == PIN_SIZE);
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aes_len == AES_KEY_LEN_256);

    // At this point we should have encrypted keys persisted in the flash
    JADE_ASSERT(keychain_has_pin());

    const uint8_t pin_attempts_remaining = keychain_pin_attempts_remaining();
    JADE_ASSERT(pin_attempts_remaining > 0); // Shouldn't be here otherwise
    JADE_LOGD("pin attempts remaining: %u", pin_attempts_remaining);

    const char* msg = NULL;
    switch (pin_attempts_remaining) {
    case 2:
        msg = "Two attempts remaining";
        break;
    case 1:
        msg = "Final attempt";
        break;
    default:
        msg = NULL;
    }

    pin_insert_t pin_insert = { .initial_state = RANDOM, .pin_digits_shown = false };
    JADE_ASSERT(sizeof(pin_insert.pin) == pin_len);
    make_pin_insert_activity(&pin_insert, title, msg);
    JADE_ASSERT(pin_insert.activity);
    SENSITIVE_PUSH(&pin_insert, sizeof(pin_insert_t));

    // If getting PIN via QRs, free gui memory before attempting QR roundtrip
    gui_set_current_activity_ex(pin_insert.activity, process->ctx.source == SOURCE_INTERNAL);

    // In a debug unattended ci build, use hardcoded pin after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    if (!run_pin_entry_loop(&pin_insert)) {
        // User abandoned entering pin
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User abandonded pin entry", NULL);
        SENSITIVE_POP(&pin_insert);
        return false;
    }
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const uint8_t testpin[sizeof(pin_insert.pin)] = { 0, 1, 2, 3, 4, 5 };
    memcpy(pin_insert.pin, testpin, sizeof(testpin));
#endif
    memcpy(pin, pin_insert.pin, sizeof(pin_insert.pin));
    SENSITIVE_POP(&pin_insert);

    const char* message[] = { "Checking..." };
    display_message_activity(message, 1);

    // Do the pinserver 'getpin' process
    // NOTE: in case of server or networking error, the reply message will be sent
    return pinclient_get(process, pin, pin_len, aeskey, aes_len);
}

static bool set_pin_get_aeskey(jade_process_t* process, const char* title, uint8_t* pin, const size_t pin_len,
    uint8_t* aeskey, const size_t aes_len)
{
    JADE_ASSERT(process);
    JADE_ASSERT(title);
    JADE_ASSERT(pin);
    JADE_ASSERT(pin_len == PIN_SIZE);
    JADE_ASSERT(aeskey);
    JADE_ASSERT(aes_len == AES_KEY_LEN_256);

    // Enter PIN to lock mnemonic/key material.
    // In a debug unattended ci build, use hardcoded pin after a short delay
    pin_insert_t pin_insert = { .initial_state = RANDOM, .pin_digits_shown = false };
    JADE_ASSERT(sizeof(pin_insert.pin) == pin_len);
    make_pin_insert_activity(&pin_insert, title, NULL);
    JADE_ASSERT(pin_insert.activity);
    SENSITIVE_PUSH(&pin_insert, sizeof(pin_insert_t));

    while (true) {
        reset_pin(&pin_insert, title);

        // If getting PIN via QRs, free gui memory before attempting QR roundtrip
        gui_set_current_activity_ex(pin_insert.activity, process->ctx.source == SOURCE_INTERNAL);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        if (!run_pin_entry_loop(&pin_insert)) {
            // User abandoned setting new pin
            jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User abandoned setting new PIN", NULL);
            SENSITIVE_POP(&pin_insert);
            return false;
        }
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const uint8_t testpin[sizeof(pin_insert.pin)] = { 0, 1, 2, 3, 4, 5 };
        memcpy(pin_insert.pin, testpin, sizeof(testpin));
#endif

        // this is the first pin, copy it and clear screen fields and have the user confirm
        memcpy(pin, pin_insert.pin, sizeof(pin_insert.pin));
        reset_pin(&pin_insert, "Confirm PIN");

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        if (!run_pin_entry_loop(&pin_insert)) {
            // User abandoned second input - back to first ...
            continue;
        }
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        memcpy(pin_insert.pin, testpin, sizeof(testpin));
#endif

        // check that the two pins are the same
        JADE_LOGD("Checking pins match");
        if (!sodium_memcmp(pin, pin_insert.pin, sizeof(pin_insert.pin))) {
            // Pins match
            JADE_LOGI("New pin confirmed");
            break;
        } else {
            // Pins mismatch - try again
            const char* message[] = { "Pin mismatch,", "please try again." };
            if (!await_continueback_activity(NULL, message, 2, true, NULL)) {
                // Abandon setting new pin
                jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User abandoned setting new PIN", NULL);
                SENSITIVE_POP(&pin_insert);
                return false;
            }
        }
    }
    SENSITIVE_POP(&pin_insert);

    const char* message[] = { "Persisting PIN data..." };
    display_message_activity(message, 1);

    // Do the pinserver 'setpin' process
    // NOTE: in case of server or networking error, the reply message will be sent
    return pinclient_set(process, pin, pin_len, aeskey, aes_len);
}

static bool get_pin_load_keys(jade_process_t* process, const bool suppress_pin_change_confirmation)
{
    JADE_ASSERT(process);

    // At this point we should have encrypted keys persisted in the flash but
    // *NOT* have any keys in-memory.  We need the pinserver data to decrypt.
    JADE_ASSERT(!keychain_get());
    JADE_ASSERT(keychain_has_pin());
    bool rslt = false;

    uint8_t pin[PIN_SIZE];
    SENSITIVE_PUSH(pin, sizeof(pin));
    uint8_t aeskey[AES_KEY_LEN_256];
    SENSITIVE_PUSH(aeskey, sizeof(aeskey));

    // Do the pinserver 'getpin' process
    const char* unlock_pin_msg = suppress_pin_change_confirmation ? "Enter Current PIN" : "Unlock Jade";
    if (!get_pin_get_aeskey(process, unlock_pin_msg, pin, sizeof(pin), aeskey, sizeof(aeskey))) {
        // User abandoned entering PIN, or some sort of server or networking/connection error
        // NOTE: reply message will have already been sent
        goto cleanup;
    }

    // Load wallet master key from flash
    if (!keychain_load(aeskey, sizeof(aeskey))) {
        JADE_LOGE("Failed to load keys - Incorrect PIN");

        // Handle this being the 'erase' pin
        check_wallet_erase_pin(process, pin, sizeof(pin));

        jade_process_reply_to_message_fail(process);

        const char* message[] = { "Incorrect PIN!" };
        await_error_activity(message, 1);
        goto cleanup;
    }

    // See if we additionally need a passphrase from the user
    if (keychain_requires_passphrase()) {
        // Loading from storage succeeded, but we still have no wallet keys.
        // May require the input of a user passphrase also.
        char passphrase[PASSPHRASE_MAX_LEN + 1];
        SENSITIVE_PUSH(passphrase, sizeof(passphrase));
        passphrase[0] = '\0';

        // Get any passphrase that may be required
        get_passphrase(passphrase, sizeof(passphrase));

        display_processing_message_activity();

        if (!keychain_complete_derivation_with_passphrase(passphrase)) {
            SENSITIVE_POP(passphrase);
            JADE_LOGE("Failed to derive wallet");
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to derive wallet", NULL);

            const char* message[] = { "Failed to derive wallet" };
            await_error_activity(message, 1);
            goto cleanup;
        }
        SENSITIVE_POP(passphrase);
    }

    // Re-set the (loaded) keychain in order to confirm the 'source'
    // (ie interface) which we will accept receiving messages from.
    // (This also clears any temporarily cached mnemonic entropy data)
    keychain_set(keychain_get(), process->ctx.source, false);
    rslt = true;

    // Optionally change PIN
    if (change_pin_requested) {
        const char* question[] = { "Do you want to", "change your PIN?" };
        if (suppress_pin_change_confirmation || await_yesno_activity("Change PIN", question, 2, true, NULL)) {
            uint8_t aeskey_new[AES_KEY_LEN_256];
            SENSITIVE_PUSH(aeskey_new, sizeof(aeskey_new));

            if (set_pin_get_aeskey(process, "Enter New PIN", pin, sizeof(pin), aeskey_new, sizeof(aeskey_new))) {
                JADE_LOGI("PIN changed on server");
                if (keychain_reencrypt(aeskey, sizeof(aeskey), aeskey_new, sizeof(aeskey_new))) {
                    const char* message[] = { "PIN changed" };
                    await_message_activity(message, 1);
                } else {
                    JADE_LOGE("Failed to re-encrypt with changed PIN data");
                    const char* message[] = { "Failed to re-encypt key data!" };
                    await_error_activity(message, 1);
                }
            } else {
                JADE_LOGW("Abandoned change-PIN");
                const char* message[] = { "Change-PIN abandoned" };
                await_error_activity(message, 1);
            }
            SENSITIVE_POP(aeskey_new);
        }
    }

    // All good
    set_request_change_pin(false); // clear flag
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(aeskey);
    SENSITIVE_POP(pin);
    return rslt;
}

static bool set_pin_save_keys(jade_process_t* process)
{
    // At this point we should have keys in-memory, but should *NOT* have
    // any encrypted keys persisted in the flash memory - ie. no PIN set.
    JADE_ASSERT(keychain_get());
    JADE_ASSERT(!keychain_has_pin());
    JADE_ASSERT(!keychain_has_temporary());
    bool rslt = false;

    uint8_t pin[PIN_SIZE];
    SENSITIVE_PUSH(pin, sizeof(pin));
    uint8_t aeskey[AES_KEY_LEN_256];
    SENSITIVE_PUSH(aeskey, sizeof(aeskey));

    // Do the pinserver 'setpin' process
    if (!set_pin_get_aeskey(process, "Enter New PIN", pin, sizeof(pin), aeskey, sizeof(aeskey))) {
        // User abandoned entering PIN, or some sort of server or networking/connection error
        // NOTE: reply message will have already been sent
        goto cleanup;
    }

    // Persist wallet master key (or mnemonic entropy if passphrase-protected) to flash memory
    if (!keychain_store(aeskey, sizeof(aeskey))) {
        JADE_LOGE("Failed to store key data encrypted in flash memory!");
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to store key data encrypted in flash memory", NULL);

        const char* message[] = { "Failed to persist key data" };
        await_error_activity(message, 1);
        goto cleanup;
    }

    // Re-set the (same) keychain in order to confirm the 'source'
    // (ie interface) which we will accept receiving messages from.
    // (This also clears any temporarily cached mnemonic entropy data)
    keychain_set(keychain_get(), process->ctx.source, false);
    rslt = true;

    // All good
    set_request_change_pin(false); // clear flag
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(aeskey);
    SENSITIVE_POP(pin);
    return rslt;
}

void auth_user_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "auth_user");
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    // Can optionally include epoch time to set internal clock
    if (rpc_has_field_data("epoch", &params)) {
        const char* errmsg = NULL;
        const int errcode = params_set_epoch_time(&params, &errmsg);
        if (errcode) {
            jade_process_reject_message(process, errcode, errmsg, NULL);
            goto cleanup;
        }
    }

    // Optional flag to suppress user confirmation of any pin change
    bool suppress_pin_change_confirmation = false;
    rpc_get_boolean("suppress_pin_change_confirmation", &params, &suppress_pin_change_confirmation);

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
    bool rslt = false;
    if (keychain_has_temporary()) {
        JADE_LOGI("using temporary keychain already present - skipping PIN step");
        JADE_ASSERT(keychain_get());

        if (KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)) {
            JADE_LOGI("temporary keychain already unlocked by this message-source");
            jade_process_reply_to_message_ok(process);
            rslt = true;
        } else if (keychain_get_userdata() == SOURCE_NONE) {
            // First use of this temporary wallet
            // Re-set the (same) keychain in order to confirm the 'source'
            // (ie interface) which we will accept receiving messages from.
            JADE_LOGI("First use of temporary keychain, associating with this message-source");
            keychain_set(keychain_get(), process->ctx.source, true);
            jade_process_reply_to_message_ok(process);
            rslt = true;
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
            rslt = true;
        } else {
            JADE_LOGI("keychain locked for this source, requesting pin");
            if (keychain_get()) {
                keychain_clear();
            }
            rslt = get_pin_load_keys(process, suppress_pin_change_confirmation);
        }
    } else {
        // Jade hw is not fully initialised - if we have an 'in-memory' mnemonic
        // then offer to persist that (with PIN and key derived with the pinserver)
        if (!keychain_get()) {
            // No (in-memory) mnemonic has been set, offer to do that now
            // (This is not ideal as can take a long time and host app is
            // waiting for a message reply and may time out.)
            JADE_LOGI("no wallet data, requesting mnemonic");
            const bool temporary_restore = false;
            const bool force_qr_scan = false;
            bool offer_qr_temporary = false; // unused - temporary wallet *NOT* intended here
            initialise_with_mnemonic(temporary_restore, force_qr_scan, &offer_qr_temporary);
        }

        if (!keychain_get()) {
            // No mnemonic entered, fail
            jade_process_reply_to_message_fail(process);
            goto cleanup;
        }

        JADE_LOGI("requesting new pin");
        rslt = set_pin_save_keys(process);
    }

    if (rslt) {
#ifndef CONFIG_DEBUG_MODE
        // If not a debug build, we restrict the hw to this network type
        // (In case it wasn't set at wallet creation/recovery time [older fw])
        keychain_set_network_type_restriction(networkIdToType(network_id));
#endif
        JADE_LOGI("Success");
    }

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
