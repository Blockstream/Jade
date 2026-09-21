#include "jade_assert.h"
#ifndef AMALGAMATED_BUILD
#include "gui.h"
#include "keychain.h"
#include "sensitive.h"
#include "ui.h"

#include <freertos/task.h>

#include <esp_system.h>

extern void __real_abort(void);

// Only try to show the error message once - if showing it fails and aborts
// again, go straight on to the real abort rather than looping forever
static bool abort_display_attempted = false;

void jade_abort(const char* file, const int line_n)
{
    // Clear senstitive data
    keychain_clear();
    sensitive_clear_stack();

    if (!abort_display_attempted && gui_initialized() && !gui_is_gui_task()) {
        abort_display_attempted = true;
        char details[128];
        const int ret = snprintf(details, sizeof(details), "%s:%d", file, line_n);
        const char* message[3] = { "Internal error", "", "Restarting" };
        if (ret > 0 && ret < sizeof(details)) {
            message[1] = details;
        }
        display_message_activity(message, 3);
    }

    // Brief delay before abort
    // 1) for the user to see the "Internal error" message
    // 2) to give serial writer a chance to process outstanding logging
    vTaskDelay(5000 / portTICK_PERIOD_MS);
    __real_abort();
    __builtin_unreachable();
}
#endif // AMALGAMATED_BUILD

// Wrap the real abort in the entire firmware so that ours gets called instead
// (see CMakeLists.txt) which will in turn call the real abort
// We do this so that we can clear the keychain and the sensitive stack

void __wrap_abort(void) { jade_abort("WRAPPED", 0); }
