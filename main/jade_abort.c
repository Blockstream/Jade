#include "gui.h"
#include "keychain.h"
#include "sensitive.h"
#include "ui.h"

#include <freertos/task.h>

#include <esp_system.h>

void jade_abort()
{
    // Clear senstitive data
    free_keychain();
    sensitive_clear_stack();

    if (gui_initialized()) {
        display_message_activity("Internal error - restarting");
    }

    // Brief delay before abort
    // 1) for the user to see the "Internal error" message
    // 2) to give serial writer a chance to process outstanding logging
    vTaskDelay(5000 / portTICK_PERIOD_MS);
    abort();
}
