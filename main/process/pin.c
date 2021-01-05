#include "../button_events.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include <string.h>

#include "process_utils.h"

// Pinserver interaction
bool pinclient_loadkeys(jade_process_t* process, const uint8_t* pin, size_t pin_size, struct keychain_handle* khandle);

void pin_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "auth_user");

    // free any existing global keychain
    free_keychain();

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
    struct keychain_handle khandle;
    SENSITIVE_PUSH(&khandle, sizeof(khandle));
    if (pinclient_loadkeys(process, pin, sizeof(pin), &khandle)) {
        // Looks good - copy temporary keychain into a new global keychain
        // and set the current message source as the keychain userdata
        set_keychain(&khandle, process->ctx.source);
        JADE_LOGI("Success");
    } else {
        // Failed - show error and go back to boot screen
        JADE_LOGW("Get-Pin / load keys failed - bad pin");
        await_error_activity("Incorrect PIN!");
    }

    // Clear out pin and temporary keychain
    SENSITIVE_POP(&khandle);
    SENSITIVE_POP(pin);
    SENSITIVE_POP(pin_insert);
}
