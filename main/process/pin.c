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

// Pinserver interaction
bool pinclient_loadkeys(jade_process_t* process, const uint8_t* pin, size_t pin_size, keychain_t* keydata);
bool pinclient_savekeys(jade_process_t* process, const uint8_t* pin, size_t pin_size, const keychain_t* keydata);

void pin_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[strlen(TAG_LOCALTESTLIQUID) + 1];

    JADE_ASSERT(keychain_has_pin());
    ASSERT_CURRENT_MESSAGE(process, "auth_user");
    GET_MSG_PARAMS(process);

    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);

    // Check network is valid and consistent with prior usage
    // (This is just an up-front check that this wallet/device is appropriate for
    // the intended network - to catch mismatches early, rather than after PIN entry).
    CHECK_NETWORK_CONSISTENT(process, network, written);

    // free any existing global keychain
    keychain_free();

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
    // (This should load the mnemonic keys encrypted in the flash)
    keychain_t keydata;
    SENSITIVE_PUSH(&keydata, sizeof(keydata));
    if (pinclient_loadkeys(process, pin, sizeof(pin), &keydata)) {
#ifndef CONFIG_DEBUG_MODE
        // If not a debug build, we restrict the hw to this network type
        // (In case it wasn't set at wallet creation/recovery time [older fw])
        keychain_set_network_type_restriction(network);
#endif
        // Copy temporary keychain into a new global keychain and
        // set the current message source as the keychain userdata
        keychain_set(&keydata, process->ctx.source);
        JADE_LOGI("Success");
    } else {
        // Failed - show error and go back to boot screen
        JADE_LOGW("Get-Pin / load keys failed - bad pin");
        await_error_activity("Incorrect PIN!");
    }

    // Clear out pin and temporary keychain
    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(pin);
    SENSITIVE_POP(pin_insert);

cleanup:
    return;
}

void set_pin_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[strlen(TAG_LOCALTESTLIQUID) + 1];
    size_t written = 0;

    ASSERT_CURRENT_MESSAGE(process, "auth_user");
    GET_MSG_PARAMS(process);

    rpc_get_string("network", sizeof(network), &params, network, &written);
    if (written == 0 || !isValidNetwork(network)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid network from parameters", NULL);
        goto cleanup;
    }

    // At this point we should have keys in-memory, but should *NOT* have
    // any encrypted keys persisted in the flash memory - ie. no PIN set.
    JADE_ASSERT(keychain_get());
    JADE_ASSERT(!keychain_has_pin());

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
    // (This should persist the mnemonic keys encrypted in the flash)
    if (pinclient_savekeys(process, pin, sizeof(pin), keychain_get())) {
#ifndef CONFIG_DEBUG_MODE
        // If not a debug build, we restrict the hw to this network type
        keychain_set_network_type_restriction(network);
#endif
        // Re-set the (same) keychain in order to confirm the 'source'
        // (ie interface) which we will accept receiving messages from.
        keychain_set(keychain_get(), process->ctx.source);
        JADE_LOGI("Success");
    } else {
        JADE_LOGW("Set-Pin / persist keys failed.");
        await_error_activity("Failed to persist key data");
    }

    // Clear out pin and temporary keychain and mnemonic
    SENSITIVE_POP(pin);
    SENSITIVE_POP(pin_insert);

cleanup:
    return;
}
