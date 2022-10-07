#include "qrmode.h"

#include "button_events.h"
#include "gui.h"
#include "jade_assert.h"
#include "qrcode.h"

#include <string.h>

void make_show_qr_help_activity(gui_activity_t** activity_ptr, const char* url, const Icon* qr_icon);

// Display screen with help url and qr code
void display_qr_help_screen(const char* url)
{
    JADE_ASSERT(url);

    const size_t url_len = strlen(url);
    JADE_ASSERT(url_len < 78);

    // Create icon for url
    // For sizes, see: https://www.qrcode.com/en/about/version.html - 'Binary'
    const uint8_t qr_version = url_len < 32 ? 2 : 4;
    const uint8_t scale_factor = qr_version == 2 ? 4 : 3;

    // Convert url to qr code, then to Icon
    QRCode qrcode;
    uint8_t qrbuffer[140]; // opaque work area
    JADE_ASSERT(qrcode_getBufferSize(qr_version) <= sizeof(qrbuffer));
    const int qret = qrcode_initText(&qrcode, qrbuffer, qr_version, ECC_LOW, url);
    JADE_ASSERT(qret == 0);

    Icon qr_icon;
    qrcode_toIcon(&qrcode, &qr_icon, scale_factor);

    // Show, and await button click
    gui_activity_t* activity = NULL;
    make_show_qr_help_activity(&activity, url, &qr_icon);
    JADE_ASSERT(activity);
    gui_set_current_activity(activity);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_EXIT_QR_HELP, NULL, NULL, NULL, 0);
#else
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_EXIT_QR_HELP, NULL, NULL, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
#endif

    // Free the qr code icon
    qrcode_freeIcon(&qr_icon);
}
