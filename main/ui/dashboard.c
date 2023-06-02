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
    gui_make_fill(&node, TFT_BLOCKSTREAM_DARKGREEN);
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
    gui_make_fill(&node, TFT_BLOCKSTREAM_DARKGREEN);
    gui_set_parent(node, hsplit);
    gui_make_text_font(item_symbol, "", TFT_WHITE, JADE_SYMBOLS_24x24_FONT);
    gui_set_align(*item_symbol, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*item_symbol, node);

    gui_make_fill(&node, TFT_BLOCKSTREAM_DARKGREEN);
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

    if (initialisation_source == SOURCE_QR) {
        // Hide back button as QR login task will have been initiated
        hdrbtns[0].txt = NULL;
        hdrbtns[0].ev_id = GUI_BUTTON_EVENT_NONE;
    }

    return make_show_message_activity(msg, 2, device_name, hdrbtns, 2, NULL, 0);
}

gui_activity_t* make_connect_qrmode_screen(const char* device_name)
{
    JADE_ASSERT(device_name);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_BACK },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CONNECT_HELP } };

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

    // Temporary restore has QR first (Jade hw only)
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
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

    // If not temporary restore, QR is last (Jade hw only)
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
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

gui_activity_t* make_bip39_passphrase_prefs_screen(
    gui_view_node_t** frequency_textbox, gui_view_node_t** method_textbox)
{
    JADE_INIT_OUT_PPTR(frequency_textbox);
    JADE_INIT_OUT_PPTR(method_textbox);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 24, 24, 24, 28);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Frequency", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_PASSPHRASE_TOGGLE_FREQUENCY, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *frequency_textbox = text;
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Method", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_PASSPHRASE_TOGGLE_METHOD, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *method_textbox = text;
    }

    {
        gui_view_node_t* filler;
        gui_make_fill(&filler, TFT_BLACK);
        gui_set_parent(filler, vsplit);
    }

    // buttons
    btn_data_t btns[] = { { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_PASSPHRASE_OPTIONS_EXIT },
        { .txt = "?", .font = GUI_DEFAULT_FONT, .ev_id = BTN_PASSPHRASE_OPTIONS_HELP } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    return act;
}

gui_activity_t* make_startup_options_screen(void)
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

gui_activity_t* make_uninitialised_settings_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    // Note: placeholder in second position - timeout button set into this slot below
    btn_data_t btns[]
        = { { .txt = "Recovery Phrase Login", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_TEMPORARY_WALLET_LOGIN },
              { .txt = "BIP39 Passphrase", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP39_PASSPHRASE },
              { .txt = "Bluetooth", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BLE },
              { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_locked_settings_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    btn_data_t btns[] = {
        { .txt = "BIP39 Passphrase", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP39_PASSPHRASE },
        { .txt = "Power Settings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_POWER_OPTIONS },
        { .txt = "Recovery Phrase Login", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_TEMPORARY_WALLET_LOGIN },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT }
    };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_unlocked_settings_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    btn_data_t btns[] = { { .txt = "Wallet", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_WALLET },
        { .txt = "Device", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE },
        { .txt = "Advanced", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_ADVANCED },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_wallet_settings_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    btn_data_t btns[] = { { .txt = "Xpub Export", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_XPUB_EXPORT },
        { .txt = "Registered Multisigs", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_MULTISIG },
        { .txt = "BIP85 Recovery Phrase", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP85 },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_WALLET_EXIT } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_device_settings_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    // Note: placeholder in first position - timeout button set into this slot below
    btn_data_t btns[] = { { .txt = "Power Settings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_POWER_OPTIONS },
        { .txt = "Bluetooth", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_BLE },
        { .txt = "Factory Reset", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_RESET },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_DEVICE_EXIT } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_power_options_screen(btn_data_t* timeout_btns, const size_t nBtns, progress_bar_t* brightness_bar)
{
    JADE_ASSERT(timeout_btns);
    JADE_ASSERT(nBtns == 7);
    JADE_ASSERT(brightness_bar);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 6, 16, 18, 4, 16, 24, 22);
#else
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 20, 25, 25, 30);
#endif
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    // Idle timeout
    {
        gui_view_node_t* text;
        gui_make_text(&text, "Idle Timeout (mins):", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, vsplit);

        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 7, 14, 14, 14, 14, 14, 14, 16);
        gui_set_parent(hsplit, vsplit);

        for (int i = 0; i < nBtns; ++i) {
            btn_data_t* const btn_info = timeout_btns + i;
            JADE_ASSERT(btn_info->txt);

            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, btn_info->ev_id, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);

            gui_view_node_t* text;
            gui_make_text_font(&text, btn_info->txt, TFT_WHITE, btn_info->font);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);

            // Set the button back in the info struct
            btn_info->btn = btn;
        }
    }

    gui_view_node_t* spacer;
    gui_make_fill(&spacer, TFT_BLACK);
    gui_set_parent(spacer, vsplit);

#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
    // Screen brightness
    {
        gui_view_node_t* text;
        gui_make_text(&text, "Screen Brightness:", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, vsplit);

        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 16, 66, 16);
        gui_set_padding(hsplit, GUI_MARGIN_TWO_VALUES, 2, 2);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* btnless;
        gui_make_button(&btnless, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_MINUS_DECREASE, NULL);
        gui_set_margins(btnless, GUI_MARGIN_ALL_EQUAL, 1);
        gui_set_parent(btnless, hsplit);
        gui_set_borders(btnless, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btnless, TFT_BLOCKSTREAM_GREEN);

        gui_view_node_t* textless;
        gui_make_text_font(&textless, "-", TFT_WHITE, GUI_DEFAULT_FONT);
        gui_set_parent(textless, btnless);
        gui_set_align(textless, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        make_progress_bar(hsplit, brightness_bar);

        gui_view_node_t* btnmore;
        gui_make_button(&btnmore, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_PLUS_INCREASE, NULL);
        gui_set_margins(btnmore, GUI_MARGIN_ALL_EQUAL, 1);
        gui_set_parent(btnmore, hsplit);
        gui_set_borders(btnmore, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btnmore, TFT_BLOCKSTREAM_GREEN);

        gui_view_node_t* textmore;
        gui_make_text_font(&textmore, "+", TFT_WHITE, GUI_DEFAULT_FONT);
        gui_set_parent(textmore, btnmore);
        gui_set_align(textmore, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }
#endif // CONFIG_BOARD_TYPE_JADE_V1_1

    // Exit btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_SETTINGS_EXIT, NULL);
        gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 0, 75);
        gui_set_parent(btn, vsplit);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);

        gui_view_node_t* text;
        gui_make_text_font(&text, "Exit", TFT_WHITE, GUI_DEFAULT_FONT);
        gui_set_parent(text, btn);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }

    return act;
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

gui_activity_t* make_advanced_options_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    btn_data_t btns[] = { { .txt = "OTP", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP },
        { .txt = "Wallet-Erase PIN", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_WALLET_ERASE_PIN },
        //{ .txt = "Nostr", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_NOSTR },  ??
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_ADVANCED_EXIT },
        { .txt = NULL, .font = JADE_SYMBOLS_16x16_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_otp_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    btn_data_t btns[] = { { .txt = "View OTPs", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_VIEW },
        { .txt = "Scan New OTP QR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_QR },
        { .txt = "Enter New OTP URI", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_KB },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_OTP_EXIT } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_pinserver_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    btn_data_t btns[]
        = { { .txt = "View PinServer Settings", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_SHOW },
              { .txt = "Scan Custom PinServer", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_SCAN_QR },
              { .txt = "Reset PinServer Defaults ", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_RESET },
              { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_PINSERVER_EXIT } };
    add_buttons(act->root_node, UI_COLUMN, btns, 4);

    return act;
}

gui_activity_t* make_session_screen(void)
{
    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 68, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, "\nLogout of current wallet or \nput Jade into sleep mode?", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_parent(text, vsplit);

    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SESSION_EXIT },
        { .txt = "Logout", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SESSION_LOGOUT },
        { .txt = "Sleep", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SESSION_SLEEP } };
    add_buttons(vsplit, UI_ROW, btns, 3);

    return act;
}

gui_activity_t* make_ble_screen(const char* device_name, gui_view_node_t** ble_status_textbox)
{
    JADE_ASSERT(device_name);
    JADE_INIT_OUT_PPTR(ble_status_textbox);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Device", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text;
        gui_make_text(&text, device_name, TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Status", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        // gui_set_borders(key, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_BLE_TOGGLE_ENABLE, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "---", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *ble_status_textbox = text;
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Pairing", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        // gui_set_borders(key, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_BLE_RESET_PAIRING, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "Reset", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_BLE_EXIT, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "Exit", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    return act;
}

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)

#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#define JADE_FCC_ID "2AWI3BLOCKSTREAMJD2"
#define MAX_LEGAL_PAGE 5
#else
#define JADE_FCC_ID "2AWI3BLOCKSTREAMJD1"
#define MAX_LEGAL_PAGE 4
#endif

static void make_legal_page(link_activity_t* page_act, int legal_page)
{
    JADE_ASSERT(page_act);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 63, 37);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 0);
    gui_set_parent(vsplit, act->root_node);

    switch (legal_page) {
    case 0: {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 35, 65);
        gui_set_padding(hsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* logo_node;
        gui_make_picture(&logo_node, &fcc);
        gui_set_parent(logo_node, hsplit);
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        gui_view_node_t* subvsplit;
        gui_make_vsplit(&subvsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(subvsplit, hsplit);

        gui_view_node_t* title;
        gui_make_text(&title, "FCC ID", TFT_WHITE);
        gui_set_parent(title, subvsplit);
        gui_set_align(title, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        gui_view_node_t* key;
        gui_make_text(&key, JADE_FCC_ID, TFT_WHITE);
        gui_set_parent(key, subvsplit);
        gui_set_align(key, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        break;
    }
    case 1: {
        gui_view_node_t* key;
        gui_make_text(&key,
            "This device complies with Part\n"
            "15 of the FCC Rules. Operation\n"
            "is subject to the following two\n"
            "conditions: (1) this device may\n"
            "not cause harmful interference",
            TFT_WHITE);
        gui_set_parent(key, vsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        break;
    }
    case 2: {
        gui_view_node_t* key;
        gui_make_text(&key,
            "and (2) this device must accept\n"
            "any interference received,\n"
            "including interference that may\n"
            "cause undesired operation.",
            TFT_WHITE);
        gui_set_parent(key, vsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        break;
    }
    case 3: {
        gui_view_node_t* logo_node;
        gui_make_picture(&logo_node, &ce);
        gui_set_parent(logo_node, vsplit);
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        break;
    }
    case 4: {
        gui_view_node_t* logo_node;
        gui_make_picture(&logo_node, &weee);
        gui_set_parent(logo_node, vsplit);
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        break;
    }
#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    case 5: {
        gui_view_node_t* logo_node;
        gui_make_picture(&logo_node, &telec);
        gui_set_parent(logo_node, vsplit);
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        break;
    }
#endif
    default: {
        JADE_ASSERT(false);
    }

    } // switch-case

    // Assume 'prev' and 'next' buttons (ok in most cases)
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_LEGAL_PREV },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_LEGAL_NEXT } };

    // Change first button to 'exit' if on first page
    if (legal_page == 0) {
        btns[0].txt = "Exit";
        btns[0].font = GUI_DEFAULT_FONT;
        btns[0].ev_id = BTN_INFO_EXIT;
    }

    // Change last button to 'exit' if on last page
    if (legal_page == MAX_LEGAL_PAGE) {
        btns[1].txt = "Exit";
        btns[1].font = GUI_DEFAULT_FONT;
        btns[1].ev_id = BTN_INFO_EXIT;
    }

    add_buttons(vsplit, UI_ROW, btns, 2);

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(act, btns[1].btn);

    // Copy activity and prev and next buttons into output struct
    page_act->activity = act;
    page_act->prev_button = (legal_page == 0) ? NULL : btns[0].btn;
    page_act->next_button = (legal_page == MAX_LEGAL_PAGE) ? NULL : btns[1].btn;
}

gui_activity_t* make_legal_screen(void)
{
    // Chain the legal screen activities
    link_activity_t page_act = {};
    linked_activities_info_t act_info = {};

    for (size_t j = 0; j <= MAX_LEGAL_PAGE; j++) {
        make_legal_page(&page_act, j);
        gui_chain_activities(&page_act, &act_info);
    }

    return act_info.first_activity;
}
#endif

gui_activity_t* make_device_screen(const char* power_status, const char* mac, const char* firmware_version)
{
    JADE_ASSERT(power_status);
    JADE_ASSERT(mac);
    JADE_ASSERT(firmware_version);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 21, 21, 21, 37);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Firmware", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text;
        gui_make_text(&text, firmware_version, TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Mac Address", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text;
        gui_make_text(&text, mac, TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Batt. Volts", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text;
        gui_make_text(&text, power_status, TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);
    }

    // 'Legal' (for genuine Jade v1.0 and v1.1), 'Storage' and 'Exit'
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    btn_data_t btns[] = { { .txt = "Legal", .font = GUI_DEFAULT_FONT, .ev_id = BTN_INFO_LEGAL },
        { .txt = "Storage", .font = GUI_DEFAULT_FONT, .ev_id = BTN_INFO_STORAGE },
        { .txt = "Exit", .font = GUI_DEFAULT_FONT, .ev_id = BTN_INFO_EXIT } };
    add_buttons(vsplit, UI_ROW, btns, 3);
#else
    btn_data_t btns[] = { { .txt = "Storage", .font = GUI_DEFAULT_FONT, .ev_id = BTN_INFO_STORAGE },
        { .txt = "Exit", .font = GUI_DEFAULT_FONT, .ev_id = BTN_INFO_EXIT } };
    add_buttons(vsplit, UI_ROW, btns, 2);
#endif

    return act;
}

gui_activity_t* make_storage_stats_screen(const size_t entries_used, const size_t entries_free)
{
    gui_activity_t* const act = gui_make_activity();

    const size_t entries_total = entries_used + entries_free;
    char buf[16];

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 20, 20, 20, 40);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 65, 35);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "Percentage Used", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);

        const int32_t pcnt_used = 100 * entries_used / entries_total;
        const int ret = snprintf(buf, sizeof(buf), "%ld%%", pcnt_used);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        gui_view_node_t* pct;
        gui_make_text(&pct, buf, TFT_WHITE);
        gui_set_align(pct, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        gui_set_parent(pct, hsplit);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 65, 35);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "Entries Used", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);

        const int ret = snprintf(buf, sizeof(buf), "%d / %d", entries_used, entries_total);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        gui_view_node_t* used;
        gui_make_text(&used, buf, TFT_WHITE);
        gui_set_align(used, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        gui_set_parent(used, hsplit);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 65, 35);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "Entries Free", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);

        const int ret = snprintf(buf, sizeof(buf), "%d", entries_free);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        gui_view_node_t* used;
        gui_make_text(&used, buf, TFT_WHITE);
        gui_set_align(used, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        gui_set_parent(used, hsplit);
    }

    {
        gui_view_node_t* row;
        gui_make_fill(&row, TFT_BLACK);
        gui_set_padding(row, GUI_MARGIN_TWO_VALUES, 4, 75);
        gui_set_parent(row, vsplit);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_INFO_EXIT, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, row);

        gui_view_node_t* text;
        gui_make_text(&text, "Exit", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    return act;
}
