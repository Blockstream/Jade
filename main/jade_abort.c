#include "gui.h"
#include "keychain.h"
#include "sensitive.h"
#include "ui.h"

#include <freertos/task.h>

#include <esp_system.h>

#define SIZE_OF_ERR_BUFF 128

void jade_abort(const char* file, const int line_n)
{
    // Clear senstitive data
    keychain_free();
    sensitive_clear_stack();

    if (gui_initialized()) {
        char details[SIZE_OF_ERR_BUFF] = { 0 };
        const int ret = snprintf(details, SIZE_OF_ERR_BUFF, "%s:%d", file, line_n);
        if (ret > 0 && ret < SIZE_OF_ERR_BUFF) {
            display_message_activity_two_lines("Internal error - restarting", details);
        } else {
            display_message_activity("Internal error - restarting");
        }
    }

    // Brief delay before abort
    // 1) for the user to see the "Internal error" message
    // 2) to give serial writer a chance to process outstanding logging
    vTaskDelay(5000 / portTICK_PERIOD_MS);
    abort();
}
