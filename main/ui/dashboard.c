#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"
#include "process.h"

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#include "../logo/ce.c"
#include "../logo/fcc.c"
#include "../logo/weee.c"
#endif

#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#include "../logo/telec.c"
#endif

gui_activity_t* make_home_screen_activity(const char* device_name, const char* firmware_version,
    gui_view_node_t** item_symbol, gui_view_node_t** item_text, gui_view_node_t** status_light,
    gui_view_node_t** status_text, gui_view_node_t** label)
{
    JADE_ASSERT(device_name);
    JADE_ASSERT(firmware_version);
    JADE_INIT_OUT_PPTR(item_symbol);
    JADE_INIT_OUT_PPTR(item_text);
    JADE_INIT_OUT_PPTR(status_light);
    JADE_INIT_OUT_PPTR(status_text);
    JADE_INIT_OUT_PPTR(label);

    // NOTE: The home screen is created as an 'unmanaged' activity as
    // its lifetime is same as that of the entire application
    gui_activity_t* act = NULL;
    gui_make_activity_ex(&act, true, device_name, false);
    JADE_ASSERT(act);

    gui_view_node_t* hsplit;
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 76, 24);
    gui_set_parent(vsplit, act->root_node);

    // Main area, scrolling horizontal menu
    gui_make_fill(&node, gui_get_highlight_color());
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 20, 0, 20, 0);
    gui_set_parent(node, vsplit);

    // l-arrow, item-symbol, item-txt, r-arrow
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 4, 10, 20, 60, 10);
    gui_set_parent(hsplit, node);

    gui_make_text_font(&node, "H", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // The items symbol and text will be updated, so we add a background that will
    // be repainted every time to wipe the previous string
    gui_make_fill(&node, gui_get_highlight_color());
    gui_set_parent(node, hsplit);
    gui_make_text_font(item_symbol, "", TFT_WHITE, JADE_SYMBOLS_24x24_FONT);
    gui_set_align(*item_symbol, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*item_symbol, node);

    gui_make_fill(&node, gui_get_highlight_color());
    gui_set_parent(node, hsplit);
    gui_make_text_font(item_text, "", TFT_WHITE, GUI_DEFAULT_FONT);
    gui_set_align(*item_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*item_text, node);

    gui_make_text_font(&node, "I", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // Footer, three labels - status light + status, fw-version/wallet-id label
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 9, 44, 47);
    gui_set_parent(hsplit, vsplit);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(status_light, "M", TFT_DARKGREY, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(*status_light, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(*status_light, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 2);
    gui_set_parent(*status_light, node);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(status_text, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*status_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*status_text, node);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(label, firmware_version, TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*label, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(*label, GUI_MARGIN_ALL_DIFFERENT, 0, 2, 0, 0);
    gui_set_parent(*label, node);

    return act;
}

gui_activity_t* make_connect_activity(const char* device_name)
{
    JADE_ASSERT(device_name);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_BACK },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CONNECT_HELP } };

    return make_show_message_activity(
        "  Connect via USB/BLE\n   to a companion app\n and select your Jade to\n  unlock with your PIN", 12,
        device_name, hdrbtns, 2, NULL, 0);
}

gui_activity_t* make_connect_to_activity(const char* device_name, const jade_msg_source_t initialisation_source)
{
    JADE_ASSERT(device_name);
    JADE_ASSERT(initialisation_source != SOURCE_INTERNAL);

    char msg[128];
    if (initialisation_source == SOURCE_BLE) {
        const int ret = snprintf(
            msg, sizeof(msg), "\n  Select %s on\n  the companion app to\n              pair it", device_name);
        JADE_ASSERT(ret > 0 && ret < sizeof(msg));
    } else {
        const int ret
            = snprintf(msg, sizeof(msg), "\n  Connect %s\n to a compatible wallet\n               app", device_name);
        JADE_ASSERT(ret > 0 && ret < sizeof(msg));
    }
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_TO_BACK },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CONNECT_HELP } };

    return make_show_message_activity(msg, 2, device_name, hdrbtns, 2, NULL, 0);
}

gui_activity_t* make_connect_qrmode_activity(const char* device_name)
{
    JADE_ASSERT(device_name);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_QR_BACK },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CONNECT_QR_HELP } };

    btn_data_t menubtns[] = { { .txt = "QR PIN Unlock", .font = GUI_DEFAULT_FONT, .ev_id = BTN_CONNECT_QR_PIN },
        { .txt = "Scan SeedQR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_CONNECT_QR_SCAN } };

    return make_menu_activity("QR Mode", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_select_connection_activity_if_required(const bool temporary_restore)
{
    // Two or three buttons, depending on whether QR and/or Bluetooth are available in the build
    // NOTE: if neither QR or BLE are an available, then the only option is USB, and this call returns null.
    // Also, a 'recovery phrase login' puts 'QR'(mode) first, whereas a standard initialisation puts QR last!

    // Initially placeholders
    btn_data_t menubtns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
    size_t ibtn = 0;

    // Temporary restore has QR first (Camera-Enabled hw only)
#ifdef CONFIG_HAS_CAMERA
    if (temporary_restore) {
        menubtns[ibtn].txt = "QR";
        menubtns[ibtn].ev_id = BTN_CONNECT_VIA_QR;
        ++ibtn;
    }
#endif

    // USB is always available
    menubtns[ibtn].txt = "USB";
    menubtns[ibtn].ev_id = BTN_CONNECT_VIA_USB;
    ++ibtn;

    // BLE if enabled in fw
#ifdef CONFIG_BT_ENABLED
    menubtns[ibtn].txt = "Bluetooth";
    menubtns[ibtn].ev_id = BTN_CONNECT_VIA_BLE;
    ++ibtn;
#endif

    // If not temporary restore, QR is last (Camera-Enabled hw only)
#ifdef CONFIG_HAS_CAMERA
    if (!temporary_restore) {
        menubtns[ibtn].txt = "QR";
        menubtns[ibtn].ev_id = BTN_CONNECT_VIA_QR;
        ++ibtn;
    }
#endif

    // For non-jade hw without BLE enabled, USB might be the only option,
    // in which case we don't really need this screen at all!
    // In this case return null here.
    if (ibtn < 2) {
        return NULL;
    }

    // Otherwise make a menu and return that
    return make_menu_activity("Select Connection", NULL, 0, menubtns, ibtn);
}

gui_activity_t* make_confirm_qrmode_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_QR_BACK },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CONNECT_QR_HELP } };

    btn_data_t ftrbtns[] = {
        { .txt = "PIN", .font = GUI_DEFAULT_FONT, .ev_id = BTN_CONNECT_QR_PIN, .borders = GUI_BORDER_TOPRIGHT },
        { .txt = "SeedQR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_CONNECT_QR_SCAN, .borders = GUI_BORDER_TOPLEFT }
    };

    gui_activity_t* const act = make_show_message_activity(
        "Save and encrypt wallet\n     with PIN or scan a\n SeedQR every session?", 12, NULL, hdrbtns, 2, ftrbtns, 2);

    return act;
}

gui_activity_t* make_bip39_passphrase_prefs_activity(
    gui_view_node_t** frequency_textbox, gui_view_node_t** method_textbox)
{
    JADE_INIT_OUT_PPTR(frequency_textbox);
    JADE_INIT_OUT_PPTR(method_textbox);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_PASSPHRASE_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_PASSPHRASE_HELP } };

    // menu buttons with bespoke content
    gui_make_text(frequency_textbox, "Frequency", TFT_WHITE);
    gui_set_align(*frequency_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_text(method_textbox, "Method", TFT_WHITE);
    gui_set_align(*method_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    btn_data_t menubtns[] = { { .content = *frequency_textbox, .ev_id = BTN_PASSPHRASE_FREQUENCY },
        { .content = *method_textbox, .ev_id = BTN_PASSPHRASE_METHOD } };

    return make_menu_activity("BIP39 Passphrase", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_startup_options_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Factory Reset", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_RESET },
        { .txt = "Blind Oracle", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER },
        { .txt = "Legal", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_LEGAL } };

    // Legal screens only apply to proper jade hw
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    const size_t num_menubtns = 3;
#else
    const size_t num_menubtns = 2;
#endif

    return make_menu_activity("Boot Menu", hdrbtns, 2, menubtns, num_menubtns);
}

gui_activity_t* make_uninitialised_settings_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[]
        = { { .txt = "Temporary Signer", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_TEMPORARY_WALLET_LOGIN },
              { .txt = "BIP39 Passphrase", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP39_PASSPHRASE },
              { .txt = "Settings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PREFS } };

    return make_menu_activity("Options", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_locked_settings_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[]
        = { { .txt = "BIP39 Passphrase", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP39_PASSPHRASE },
              { .txt = "Device", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE },
              { .txt = "Temporary Signer", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_TEMPORARY_WALLET_LOGIN } };

    return make_menu_activity("Options", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_unlocked_settings_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Wallet", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_WALLET },
        { .txt = "Device", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE },
        { .txt = "Authentication", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_AUTHENTICATION } };

    return make_menu_activity("Options", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_wallet_settings_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_WALLET_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Export Xpub", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_XPUB_EXPORT },
        { .txt = "Registered Wallets", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_REGISTERED_WALLETS },
        { .txt = "BIP85", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP85 } };

    return make_menu_activity("Wallet", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_device_settings_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_DEVICE_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Settings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PREFS },
        { .txt = "Factory Reset", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_RESET },
        { .txt = "Info", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_INFO } };

    return make_menu_activity("Device", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_prefs_settings_activity(const bool show_ble)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_PREFS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Display", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DISPLAY },
        { .txt = "Idle Timeout", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_IDLE_TIMEOUT },
        { .txt = "Bluetooth", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BLE } };
    const size_t num_menubtns = show_ble ? 3 : 2;

    return make_menu_activity("Settings", hdrbtns, 2, menubtns, num_menubtns);
}

gui_activity_t* make_display_settings_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_DISPLAY_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // NOTE: Only Jade v1.1's have brightness controls
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    btn_data_t menubtns[]
        = { { .txt = "Display Brightness", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DISPLAY_BRIGHTNESS },
              { .txt = "Theme", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DISPLAY_THEME } };
    const size_t num_menubtns = 2;
#else
    btn_data_t menubtns[] = { { .txt = "Theme", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DISPLAY_THEME } };
    const size_t num_menubtns = 1;
#endif

    return make_menu_activity("Display", hdrbtns, 2, menubtns, num_menubtns);
}

gui_activity_t* make_authentication_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_AUTHENTICATION_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Duress PIN", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_WALLET_ERASE_PIN },
        { .txt = "OTP", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP } };

    return make_menu_activity("Authentication", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_otp_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_OTP_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_SETTINGS_OTP_HELP } };

    btn_data_t menubtns[] = { { .txt = "View OTP", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_VIEW },
        { .txt = "New OTP Record", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW } };

    return make_menu_activity("OTP", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_new_otp_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_SETTINGS_OTP_HELP } };

    btn_data_t menubtns[] = { { .txt = "Scan QR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_QR },
        { .txt = "Enter URI", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_KB } };

    return make_menu_activity("New OTP", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_pinserver_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_PINSERVER_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_SETTINGS_PINSERVER_HELP } };

    btn_data_t menubtns[] = { { .txt = "Settings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_SHOW },
        { .txt = "Scan Oracle QR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_SCAN_QR },
        { .txt = "Reset Oracle", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_RESET } };

    return make_menu_activity("Blind Oracle", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_wallet_erase_pin_info_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_WALLET_ERASE_PIN_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_WALLET_ERASE_PIN_HELP } };

    btn_data_t ftrbtn
        = { .txt = "Continue", .font = GUI_DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_SET, .borders = GUI_BORDER_TOP };

    gui_activity_t* const act
        = make_show_message_activity("A duress PIN will delete\n    the wallet stored on\n        Jade if entered", 12,
            "Wallet-Erase PIN", hdrbtns, 2, &ftrbtn, 1);

    // Set the intially selected item to the 'Continue' button
    gui_set_activity_initial_selection(act, ftrbtn.btn);

    return act;
}

gui_activity_t* make_wallet_erase_pin_options_activity(gui_view_node_t** pin_text)
{
    JADE_INIT_OUT_PPTR(pin_text);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_WALLET_ERASE_PIN_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_WALLET_ERASE_PIN_HELP } };

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, "Wallet-Erase PIN", hdrbtns, 2, NULL);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 35, 35, 30);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 8, 0, 8, 0);
    gui_set_parent(vsplit, parent);

    gui_view_node_t* label;
    gui_make_text(&label, "Wallet-erase PIN set:", TFT_WHITE);
    gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(label, vsplit);

    gui_make_text(pin_text, "", TFT_WHITE);
    gui_set_align(*pin_text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    gui_set_parent(*pin_text, vsplit);

    btn_data_t ftrbtns[] = { { .txt = "Change", .font = GUI_DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_SET },
        { .txt = "Disable", .font = GUI_DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_DISABLE } };
    add_buttons(vsplit, UI_ROW, ftrbtns, 2);

    return act;
}

gui_activity_t* make_session_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SESSION_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Logout", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SESSION_LOGOUT }
#ifndef CONFIG_ETH_USE_OPENETH
        ,
        { .txt = "Sleep", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SESSION_SLEEP }
#endif
    };

    return make_menu_activity("Session", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_ble_activity(gui_view_node_t** ble_status_item)
{
    JADE_INIT_OUT_PPTR(ble_status_item);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BLE_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_BLE_HELP } };

    // menu buttons with bespoke content
    gui_make_text(ble_status_item, "Status:", TFT_WHITE);
    gui_set_align(*ble_status_item, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    btn_data_t menubtns[] = { { .content = *ble_status_item, .ev_id = BTN_BLE_STATUS },
        { .txt = "Reset Pairings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BLE_RESET_PAIRING } };

    return make_menu_activity("Bluetooth", hdrbtns, 2, menubtns, 2);
}

gui_activity_t* make_view_delete_wallet_activity(const char* wallet_name, const bool allow_export)
{
    JADE_ASSERT(wallet_name);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Details", .font = GUI_DEFAULT_FONT, .ev_id = BTN_VIEW_WALLET },
        { .txt = "Delete", .font = GUI_DEFAULT_FONT, .ev_id = BTN_DELETE_WALLET },
        { .txt = "Delete", .font = GUI_DEFAULT_FONT, .ev_id = BTN_DELETE_WALLET } };

    if (allow_export) {
        menubtns[1].txt = "Export";
        menubtns[1].ev_id = BTN_EXPORT_WALLET;
    }

    return make_menu_activity(wallet_name, hdrbtns, 2, menubtns, allow_export ? 3 : 2);
}

gui_activity_t* make_info_activity(const char* fw_version)
{
    JADE_ASSERT(fw_version);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_INFO_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // menu buttons with bespoke content
    const size_t fwlen = strlen(fw_version);
    const uint32_t fwsplitsize = fwlen > 8 ? 44 : 60;
    gui_view_node_t* splitfw;
    gui_make_hsplit(&splitfw, GUI_SPLIT_RELATIVE, 2, fwsplitsize, 100 - fwsplitsize);

    gui_view_node_t* fwver;
    gui_make_text(&fwver, "Firmware:", TFT_WHITE);
    gui_set_align(fwver, GUI_ALIGN_MIDDLE, GUI_ALIGN_MIDDLE);
    gui_set_parent(fwver, splitfw);

    gui_make_text(&fwver, fw_version, TFT_WHITE);
    gui_set_align(fwver, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(fwver, splitfw);

    btn_data_t menubtns[] = { { .content = splitfw, .ev_id = BTN_SETTINGS_INFO_FWVERSION },
        { .txt = "Device Info", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE_INFO },
        { .txt = "Legal", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_LEGAL } };

    // Legal screens only apply to proper jade hw
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    const size_t num_menubtns = 3;
#else
    const size_t num_menubtns = 2;
#endif

    gui_activity_t* const act = make_menu_activity("Info", hdrbtns, 2, menubtns, num_menubtns);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(fwver, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

gui_activity_t* make_device_info_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_DEVICE_INFO_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "MAC Address", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE_INFO_MAC },
        { .txt = "Battery Volts", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE_INFO_BATTERY },
        { .txt = "Storage", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE_INFO_STORAGE } };

    return make_menu_activity("Device Info", hdrbtns, 2, menubtns, 3);
}

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)

#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#define JADE_FCC_ID "2AWI3BLOCK\n STREAMJD2"
#define MAX_LEGAL_PAGE 6
#else
#define JADE_FCC_ID "2AWI3BLOCK\n STREAMJD1"
#define MAX_LEGAL_PAGE 5
#endif

static void make_legal_page(link_activity_t* page_act, int legal_page)
{
    JADE_ASSERT(page_act);

    const bool first_page = (legal_page == 0);
    const bool last_page = (legal_page == MAX_LEGAL_PAGE);

    // 'prev' and 'next' buttons - give 'exit' event on first/last page
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = first_page ? BTN_LEGAL_EXIT : BTN_LEGAL_PREV },
              { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = last_page ? BTN_LEGAL_EXIT : BTN_LEGAL_NEXT } };

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, "Certifications", hdrbtns, 2, NULL);
    gui_view_node_t* node;

    switch (legal_page) {
    case 0: {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 35, 65);
        gui_set_padding(hsplit, GUI_MARGIN_ALL_DIFFERENT, 8, 4, 2, 4);
        gui_set_parent(hsplit, parent);

        gui_make_picture(&node, &fcc);
        gui_set_parent(node, hsplit);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 30, 70);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* title;
        gui_make_text(&title, "FCC ID", TFT_WHITE);
        gui_set_parent(title, vsplit);
        gui_set_align(title, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        gui_make_text(&node, JADE_FCC_ID, TFT_WHITE);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 8, 0, 0, 12);
        gui_set_parent(node, vsplit);
        gui_set_align(node, GUI_ALIGN_TOP, GUI_ALIGN_LEFT);
        break;
    }
    case 1: {
        gui_make_text(&node,
            "This device complies\n"
            "with Part 15 of the FCC\n"
            "rules. Operation is\n"
            "subject to the following\n"
            "two conditions: (1) this",
            TFT_WHITE);
        gui_set_parent(node, parent);
        gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 8, 0, 0, 4);
        break;
    }
    case 2: {
        gui_view_node_t* key;
        gui_make_text(&key,
            "device may not cause\n"
            "harmful interference\n"
            "and (2) this device\n"
            "must accept any\n"
            "interference received",
            TFT_WHITE);
        gui_set_parent(key, parent);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 8, 0, 0, 4);
        break;
    }
    case 3: {
        gui_view_node_t* key;
        gui_make_text(&key,
            "including interference\n"
            "that may cause\n"
            "undesired operation.",
            TFT_WHITE);
        gui_set_parent(key, parent);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 8, 0, 0, 4);
        break;
    }
    case 4: {
        gui_make_picture(&node, &ce);
        gui_set_parent(node, parent);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_padding(node, GUI_MARGIN_ALL_EQUAL, 12);
        break;
    }
    case 5: {
        gui_make_picture(&node, &weee);
        gui_set_parent(node, parent);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_padding(node, GUI_MARGIN_ALL_EQUAL, 12);
        break;
    }
#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    case 6: {
        gui_make_picture(&node, &telec);
        gui_set_parent(node, parent);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_padding(node, GUI_MARGIN_ALL_EQUAL, 12);
        break;
    }
#endif
    default: {
        JADE_ASSERT(false);
    }
    }

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(act, hdrbtns[1].btn);

    // Copy activity and prev and next buttons into output struct
    page_act->activity = act;
    page_act->prev_button = first_page ? NULL : hdrbtns[0].btn;
    page_act->next_button = last_page ? NULL : hdrbtns[1].btn;
}

gui_activity_t* make_legal_certifications_activity(void)
{
    // Chain the legal screen activities
    link_activity_t page_act = {};
    linked_activities_info_t act_info = {};

    for (size_t j = 0; j <= MAX_LEGAL_PAGE; ++j) {
        make_legal_page(&page_act, j);
        gui_chain_activities(&page_act, &act_info);
    }

    return act_info.first_activity;
}
#endif

gui_activity_t* make_storage_stats_activity(const size_t entries_used, const size_t entries_free)
{
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_DEVICE_INFO_STORAGE_EXIT },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, "Storage", hdrbtns, 2, NULL);
    gui_view_node_t* hsplit;
    gui_view_node_t* node;

    const size_t entries_total = entries_used + entries_free;
    char buf[16];

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, parent);

    // % used
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 75, 25);
    gui_set_parent(hsplit, vsplit);

    gui_make_text(&node, "Percentage Used", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    const int32_t pcnt_used = 100 * entries_used / entries_total;
    int ret = snprintf(buf, sizeof(buf), "%ld%%", pcnt_used);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));

    gui_make_text(&node, buf, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // Entries used
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 60, 40);
    gui_set_parent(hsplit, vsplit);

    gui_make_text(&node, "Entries Used", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    ret = snprintf(buf, sizeof(buf), "%d / %d", entries_used, entries_total);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));

    gui_make_text(&node, buf, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // Entries free
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 60, 40);
    gui_set_parent(hsplit, vsplit);

    gui_make_text(&node, "Entries Free", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    ret = snprintf(buf, sizeof(buf), "%d", entries_free);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));

    gui_make_text(&node, buf, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    return act;
}
