#include "qrmode.h"

#include "bcur.h"
#include "button_events.h"
#include "gui.h"
#include "jade_assert.h"
#include "qrcode.h"
#include "storage.h"

#include <string.h>

void make_show_qr_help_activity(gui_activity_t** activity_ptr, const char* url, Icon* qr_icon);

void make_show_xpub_qr_activity(gui_activity_t** activity_ptr, const char* label, const char* pathstr, Icon* icons,
    const size_t num_icons, const size_t frames_per_qr_icon);
void make_xpub_qr_options_activity(gui_activity_t** activity_ptr, gui_view_node_t** script_textbox,
    gui_view_node_t** multisig_textbox, gui_view_node_t** urtype_textbox);

#define EXPORT_XPUB_PATH_LEN 4

// Test whether 'flags' contains the entirety of the 'test_flags'
// (ie. maybe compound/multiple bits set)
static inline bool contains_flags(const uint16_t flags, const uint16_t test_flags)
{
    return (flags & test_flags) == test_flags;
}

static uint8_t qr_animation_speed_from_flags(const uint16_t qr_flags)
{
    // Frame periods around 800ms, 450ms, 270ms  (see GUI_TARGET_FRAMERATE)
    // Frame rates: HIGH|LOW > HIGH > LOW ...
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_SPEED_HIGH | QR_SPEED_LOW) ? 4 : contains_flags(qr_flags, QR_SPEED_LOW) ? 12 : 7;
}

static uint8_t qr_version_from_flags(const uint16_t qr_flags)
{
    // QR versions 12, 6 and 4 fit well on the Jade screen with scaling of
    // 2 px-per-cell, 3 px-per-cell, and 4 px-per-cell respectively.
    // Version/Size/Density: HIGH|LOW > HIGH > LOW ... 0 implies unset/default
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_DENSITY_HIGH | QR_DENSITY_LOW) ? 12
        : contains_flags(qr_flags, QR_DENSITY_LOW)                    ? 4
                                                                      : 6;
}

// We support native segwit and p2sh-wrapped segwit, siglesig and multisig
static script_variant_t xpub_script_variant_from_flags(const uint16_t qr_flags)
{
    const bool wrapped_segwit = contains_flags(qr_flags, QR_XPUB_P2SH_WRAPPED);
    if (contains_flags(qr_flags, QR_XPUB_MULTISIG)) {
        return wrapped_segwit ? MULTI_P2WSH_P2SH : MULTI_P2WSH;
    }
    return wrapped_segwit ? MULTI_P2WSH_P2SH : MULTI_P2WSH;
}

static bool create_display_xpub_qr_activity(gui_activity_t** activity_ptr, const uint16_t qr_flags)
{
    JADE_ASSERT(activity_ptr);

    const bool use_format_hdkey = false; // qr_flags & QR_XPUB_HDKEY;  - not currently in use
    const char* const xpub_qr_format = use_format_hdkey ? BCUR_TYPE_CRYPTO_HDKEY : BCUR_TYPE_CRYPTO_ACCOUNT;
    const script_variant_t script_variant = xpub_script_variant_from_flags(qr_flags);

    // Deduce path based on script type and main/test network restrictions
    uint32_t path[EXPORT_XPUB_PATH_LEN]; // 3 or 4 - purpose'/cointype'/account'/[multisig bip48 script type']
    size_t path_len = 0;
    wallet_get_default_xpub_export_path(script_variant, path, EXPORT_XPUB_PATH_LEN, &path_len);

    // Construct BC-UR CBOR message for 'crypto-account' or 'crypto-hdkey' bcur
    uint8_t cbor[128];
    size_t written = 0;
    if (use_format_hdkey) {
        bcur_build_cbor_crypto_hdkey(path, path_len, cbor, sizeof(cbor), &written);
    } else {
        bcur_build_cbor_crypto_account(script_variant, path, path_len, cbor, sizeof(cbor), &written);
    }

    // Map BCUR cbor into a series of QR-code icons
    Icon* icons = NULL;
    size_t num_icons = 0;
    const uint8_t qrcode_version = qr_version_from_flags(qr_flags);
    bcur_create_qr_icons(cbor, written, xpub_qr_format, qrcode_version, &icons, &num_icons);

    // Create xpub activity for those icons
    char pathstr[32];
    const bool ret = bip32_path_as_str(path, path_len, pathstr, sizeof(pathstr));
    JADE_ASSERT(ret);
    const char* label = qr_flags & QR_XPUB_MULTISIG ? "Multisig" : "Singlesig";
    const uint8_t frames_per_qr = qr_animation_speed_from_flags(qr_flags);
    make_show_xpub_qr_activity(activity_ptr, label, pathstr, icons, num_icons, frames_per_qr);
    JADE_ASSERT(*activity_ptr);

    return true;
}

static bool handle_xpub_options(uint16_t* qr_flags)
{
    JADE_ASSERT(qr_flags);

    gui_activity_t* activity = NULL;
    gui_view_node_t* script_textbox = NULL;
    gui_view_node_t* multisig_textbox = NULL;
    gui_view_node_t* urtype_textbox = NULL;
    make_xpub_qr_options_activity(&activity, &script_textbox, &multisig_textbox, &urtype_textbox);
    JADE_ASSERT(activity);
    JADE_ASSERT(script_textbox);
    JADE_ASSERT(multisig_textbox);
    JADE_ASSERT(!urtype_textbox); // not currently in use

    const uint16_t initial_flags = *qr_flags;
    while (true) {
        // Update options
        gui_update_text(script_textbox, *qr_flags & QR_XPUB_P2SH_WRAPPED ? "Wrapped Segwit" : "Native Segwit");
        gui_update_text(multisig_textbox, *qr_flags & QR_XPUB_MULTISIG ? "Multisig" : "Singlesig");
        // gui_update_text(urtype_textbox, *qr_flags & QR_XPUB_HDKEY ? "HDKey" : "Account");  // not currently in use

        // Show, and await button click
        gui_set_current_activity(activity);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_XPUB_TOGGLE_SCRIPT) {
                *qr_flags ^= QR_XPUB_P2SH_WRAPPED;
            } else if (ev_id == BTN_XPUB_TOGGLE_MULTISIG) {
                *qr_flags ^= QR_XPUB_MULTISIG;
                //} else if (ev_id == BTN_XPUB_TOGGLE_BCUR_TYPE) {
                //    *qr_flags ^= QR_XPUB_HDKEY;
            } else if (ev_id == BTN_XPUB_OPTIONS_HELP) {
                display_qr_help_screen("blockstream.com/xpub");
            } else if (ev_id == BTN_XPUB_OPTIONS_EXIT) {
                // Done
                break;
            }
        }
    }

    // If nothing was updated, return false
    if (initial_flags == *qr_flags) {
        return false;
    }

    // Persist prefereces and return true to indicate they were changed
    storage_set_qr_flags(*qr_flags);
    return true;
}

// Display singlesig xpub qr code
void display_xpub_qr(void)
{
    uint16_t qr_flags = storage_get_qr_flags();

    // Create show xpub activity for those icons
    gui_activity_t* activity = NULL;
    create_display_xpub_qr_activity(&activity, qr_flags);
    JADE_ASSERT(activity);

    while (true) {
        // Show, and await button click
        gui_set_current_activity(activity);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_XPUB_OPTIONS) {
                if (handle_xpub_options(&qr_flags)) {
                    // Options were updated - re-create xpub screen
                    create_display_xpub_qr_activity(&activity, qr_flags);
                }
            } else if (ev_id == BTN_XPUB_EXIT) {
                // Done
                break;
            }
        }
    }
}

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
