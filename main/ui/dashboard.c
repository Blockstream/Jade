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

void make_startup_options_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Advanced");

    btn_data_t btns[]
        = { { .txt = "Factory Reset", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_RESET },
              { .txt = "PinServer", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER },
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
              { .txt = "Legal", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_LEGAL },
              { .txt = "Exit", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_EXIT } };
#else
              { .txt = "Exit", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_EXIT },
              { .txt = NULL, .font = DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } }; // spacer
#endif
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

// NOTE: This 'dashboard' screen is created as an 'unmanaged' activity, so it is not placed
// in the list of activities to be freed by 'set_current_activity_ex()' calls.
// It must be freed by the caller.
void make_setup_screen(gui_activity_t** activity_ptr, const char* device_name, const char* firmware_version)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);
    JADE_ASSERT(firmware_version);

    char title[32];
    const int ret = snprintf(title, sizeof(title), "Setup %s", device_name);
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    // NOTE: This 'dashboard' screen is created as an 'unmanaged' activity
    gui_make_activity_ex(activity_ptr, true, title, false);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 32, 52, 16);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    {
        gui_view_node_t* text;
        gui_make_text(&text, "For setup instructions visit\nblockstream.com/jade", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 6, 8, 0, 8);
        gui_set_parent(text, vsplit);
    }

    {
        gui_view_node_t* row;
        gui_make_fill(&row, TFT_BLACK);
        gui_set_padding(row, GUI_MARGIN_TWO_VALUES, 0, 50);
        gui_set_parent(row, vsplit);

        btn_data_t btns[] = { { .txt = "Initialize", .font = DEFAULT_FONT, .ev_id = BTN_INITIALIZE },
            { .txt = "Advanced", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS } };

        add_buttons(row, UI_COLUMN, btns, 2);
    }

    {
        gui_view_node_t* ver;
        gui_make_text(&ver, firmware_version, TFT_WHITE);
        gui_set_align(ver, GUI_ALIGN_RIGHT, GUI_ALIGN_BOTTOM);
        gui_set_padding(ver, GUI_MARGIN_ALL_DIFFERENT, 0, 8, 2, 2);
        gui_set_parent(ver, vsplit);
    }
}

void make_connect_screen(gui_activity_t** activity_ptr, const char* device_name, void* unused)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);
    JADE_ASSERT(!unused);

    char title[32];
    const int ret = snprintf(title, sizeof(title), "Connect %s", device_name);
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_make_activity(activity_ptr, true, title);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 34, 34, 32);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Text1
    gui_view_node_t* text1;
    gui_make_text(&text1, "Connect using USB or BLE to\na companion device.", TFT_WHITE);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text1, GUI_MARGIN_ALL_DIFFERENT, 8, 2, 0, 4);
    gui_set_parent(text1, vsplit);

    // Text2
    gui_view_node_t* text2;
    gui_make_text(&text2, "Select Jade on a compatible\nwallet to unlock with PIN.", TFT_WHITE);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text2, GUI_MARGIN_ALL_DIFFERENT, 4, 2, 0, 4);
    gui_set_parent(text2, vsplit);

    // Buttons
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_BACK },
        { .txt = "?", .font = DEFAULT_FONT, .ev_id = BTN_CONNECT_HELP } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}

void make_connect_qrmode_screen(gui_activity_t** activity_ptr, const char* device_name)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);

    gui_make_activity(activity_ptr, true, device_name);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 28, 72);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Text
    gui_view_node_t* text;
    gui_make_text(&text, "How do you want to access\nQR Mode ?", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 2, 0, 0, 2);
    gui_set_parent(text, vsplit);

    // Buttons
    btn_data_t btns[] = { { .txt = "QR PIN Unlock", .font = DEFAULT_FONT, .ev_id = BTN_CONNECT_QR_PIN },
        { .txt = "Scan SeedQR", .font = DEFAULT_FONT, .ev_id = BTN_CONNECT_QR_SCAN },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CONNECT_BACK } };
    add_buttons(vsplit, UI_COLUMN, btns, 3);
}

// NOTE: This 'dashboard' screen is created as an 'unmanaged' activity, so it is not placed
// in the list of activities to be freed by 'set_current_activity_ex()' calls.
// It must be freed by the caller.
void make_welcome_back_screen(gui_activity_t** activity_ptr, const char* device_name, const char* firmware_version)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);
    JADE_ASSERT(firmware_version);

    // NOTE: This 'dashboard' screen is created as an 'unmanaged' activity
    gui_make_activity_ex(activity_ptr, true, device_name, false);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 36, 32, 32);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, text
    gui_view_node_t* text;
    gui_make_text(&text, "Connect Jade to a companion\napp or choose more options", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 8, 4, 0, 4);
    gui_set_parent(text, vsplit);

    // second row, fw version
    char buf[64];
    const size_t fwverlen = strlen(firmware_version);
    const int ret = snprintf(buf, sizeof(buf), "%s%s", fwverlen <= 20 ? "Firmware: " : "", firmware_version);
    JADE_ASSERT(ret > 0); // ignore any truncation of overlong version string

    gui_view_node_t* ver;
    gui_make_text(&ver, buf, TFT_WHITE);
    gui_set_align(ver, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(ver, vsplit);

    // third row, buttons
    btn_data_t btns[] = { { .txt = "Connect", .font = DEFAULT_FONT, .ev_id = BTN_CONNECT },
        { .txt = "QR Mode", .font = DEFAULT_FONT, .ev_id = BTN_QR_MODE },
        { .txt = "Options", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS } };
    add_buttons(vsplit, UI_ROW, btns, 3);
}

void make_connection_select_screen(gui_activity_t** activity_ptr, const bool temporary_restore)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Select Connection");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 60, 40);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, "How do you want to interact\nwith your Jade?", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 12, 8, 0, 8);
    gui_set_parent(text, vsplit);

    // One, two or three buttons, depending on whether QR and/or Bluetooth are available in the build
    // Also, a 'recovery phrase login' puts 'QR'(mode) first, whereas a standard initialisation puts QR last!
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    const char* qr_label = "QR";
    const uint32_t qr_ev_id = BTN_CONNECT_VIA_QR;
#else
    const char* qr_label = NULL;
    const uint32_t qr_ev_id = GUI_BUTTON_EVENT_NONE;
#endif

#ifndef CONFIG_ESP32_NO_BLOBS
    const char* ble_label = "Bluetooth";
    const uint32_t ble_ev_id = BTN_CONNECT_VIA_BLE;
#else
    const char* ble_label = NULL;
    const uint32_t ble_ev_id = GUI_BUTTON_EVENT_NONE;
#endif

    if (temporary_restore) {
        // QR, USB, BLE
        btn_data_t btns[] = { { .txt = qr_label, .font = DEFAULT_FONT, .ev_id = qr_ev_id },
            { .txt = "USB", .font = DEFAULT_FONT, .ev_id = BTN_CONNECT_VIA_USB },
            { .txt = ble_label, .font = DEFAULT_FONT, .ev_id = ble_ev_id } };
        add_buttons(vsplit, UI_ROW, btns, 3);
    } else {
        // USB, BLE, QR
        btn_data_t btns[] = { { .txt = "USB", .font = DEFAULT_FONT, .ev_id = BTN_CONNECT_VIA_USB },
            { .txt = ble_label, .font = DEFAULT_FONT, .ev_id = ble_ev_id },
            { .txt = qr_label, .font = DEFAULT_FONT, .ev_id = qr_ev_id } };
        add_buttons(vsplit, UI_ROW, btns, 3);
    }
}

void make_connect_to_screen(
    gui_activity_t** activity_ptr, const char* device_name, const jade_msg_source_t initialisation_source)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);

    char title[32];
    const int ret = snprintf(title, sizeof(title), "Connect %s", device_name);
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_make_activity(activity_ptr, true, title);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 60, 40);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Text
    const char* message = initialisation_source == SOURCE_BLE
        ? "Select your Jade on the \ncompanion app to pair it"
        : "Connect Jade to a compatible\nwallet app\nblockstream.com/jadewallets";
    gui_view_node_t* text;
    gui_make_text(&text, message, TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 12, 8, 0, 8);
    gui_set_parent(text, vsplit);

#ifndef CONFIG_ESP32_NO_BLOBS
    if (initialisation_source != SOURCE_QR) {
        // Back button
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_CONNECT_TO_BACK, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_margins(btn, GUI_MARGIN_ALL_DIFFERENT, 15, 150, 0, 8);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* btntext;
        gui_make_text_font(&btntext, "=", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
        gui_set_align(btntext, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(btntext, btn);
    }
#endif
}

// NOTE: The main 'Ready' screen is created as an 'unmanaged' activity, so it is not placed
// in the list of activities to be freed by 'set_current_activity_ex()' calls.
// This is becase the 'Ready' screen is never freed and lives as long as the application itself.
void make_ready_screen(
    gui_activity_t** activity_ptr, const char* device_name, gui_view_node_t** txt_label, gui_view_node_t** txt_extra)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);
    JADE_INIT_OUT_PPTR(txt_label);
    JADE_INIT_OUT_PPTR(txt_extra);

    // NOTE: This 'dashboard' screen is created as an 'unmanaged' activity
    gui_make_activity_ex(activity_ptr, true, device_name, false);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 40, 25, 35);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    gui_view_node_t* row1;
    gui_make_fill(&row1, TFT_BLACK);
    gui_set_parent(row1, vsplit);

    gui_view_node_t* label_text;
    gui_make_text(&label_text, "", TFT_WHITE);
    gui_set_align(label_text, GUI_ALIGN_CENTER, GUI_ALIGN_BOTTOM);
    gui_set_parent(label_text, row1);
    *txt_label = label_text;

    gui_view_node_t* row2;
    gui_make_fill(&row2, TFT_BLACK);
    gui_set_parent(row2, vsplit);

    gui_view_node_t* extra_text;
    gui_make_text(&extra_text, "", TFT_WHITE);
    gui_set_align(extra_text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    gui_set_parent(extra_text, row2);
    *txt_extra = extra_text;

    // Make the button bar under the passed node, and add all the buttons
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 4, 28, 27, 29, 16);
    gui_set_parent(hsplit, vsplit);

    // session btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_SESSION, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Session", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // options btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Options", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // scan btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_SCAN_QR, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "QR Scan", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // info btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_INFO, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Info", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }
}

void make_bip39_passphrase_prefs_screen(
    gui_activity_t** activity_ptr, gui_view_node_t** frequency_textbox, gui_view_node_t** method_textbox)
{
    JADE_ASSERT(activity_ptr);
    JADE_INIT_OUT_PPTR(frequency_textbox);
    JADE_INIT_OUT_PPTR(method_textbox);

    gui_make_activity(activity_ptr, true, "BIP39 Passphrase");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 24, 24, 24, 28);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Frequency", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_PASSPHRASE_TOGGLE_FREQUENCY, NULL);
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
        gui_make_button(&btn, TFT_BLACK, BTN_PASSPHRASE_TOGGLE_METHOD, NULL);
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
        { .txt = "?", .font = DEFAULT_FONT, .ev_id = BTN_PASSPHRASE_OPTIONS_HELP } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}

void make_uninitialised_settings_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Advanced");

    // Note: placeholder in second position - timeout button set into this slot below
    btn_data_t btns[]
        = { { .txt = "Recovery Phrase Login", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TEMPORARY_WALLET_LOGIN },
              { .txt = "BIP39 Passphrase", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP39_PASSPHRASE },
              { .txt = "Bluetooth", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_BLE },
              { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_locked_settings_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Options");

    btn_data_t btns[] = { { .txt = "BIP39 Passphrase", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP39_PASSPHRASE },
        { .txt = "Idle Timeout", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_IDLE_TIMEOUT },
        { .txt = "Recovery Phrase Login", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TEMPORARY_WALLET_LOGIN },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_unlocked_settings_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Options");

    btn_data_t btns[] = { { .txt = "Wallet", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_WALLET },
        { .txt = "Device", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_DEVICE },
        { .txt = "Advanced", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_ADVANCED },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_wallet_settings_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Wallet");

    btn_data_t btns[] = { { .txt = "Xpub Export", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_XPUB_EXPORT },
        { .txt = "Registered Multisigs", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_MULTISIG },
        { .txt = "BIP85 Recovery Phrase", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_BIP85 },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_WALLET_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_device_settings_screen(gui_activity_t** activity_ptr, gui_view_node_t** timeout_btn_text)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(timeout_btn_text);

    gui_make_activity(activity_ptr, true, "Device");

    // Note: placeholder in first position - timeout button set into this slot below
    btn_data_t btns[]
        = { { .txt = NULL, .font = DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // placeholder for timeout
              { .txt = "Bluetooth", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_BLE },
              { .txt = "Factory Reset", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_RESET },
              { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_DEVICE_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);

    // Put special timeout button in the 1st position
    gui_view_node_t* btn;
    gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS_IDLE_TIMEOUT, NULL);
    gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_parent(btn, btns[0].btn);

    gui_view_node_t* text;
    gui_make_text(&text, "Idle Timeout", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text, btn);

    *timeout_btn_text = text;
}

void make_idle_timeout_screen(gui_activity_t** activity_ptr, btn_data_t* timeout_btns, const size_t nBtns)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(timeout_btns);
    JADE_ASSERT(nBtns == 6);

    gui_make_activity(activity_ptr, true, "Idle Timeout");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    {
        gui_view_node_t* text;
        gui_make_text(&text, "Idle Timeout (mins)", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, vsplit);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 6, 16, 16, 16, 16, 18, 18);
        gui_set_parent(hsplit, vsplit);

        for (int i = 0; i < nBtns; ++i) {
            btn_data_t* const btn_info = timeout_btns + i;
            JADE_ASSERT(btn_info->txt);

            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, btn_info->ev_id, NULL);
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
}

void make_wallet_erase_pin_info_activity(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Wallet-Erase PIN");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    const char* msg = "A wallet-erase PIN will erase the\nrecovery phrase and show\n\"Internal Error\".\nMake sure "
                      "your recovery\nphrase is backed up.";

    gui_view_node_t* text;
    gui_make_text(&text, msg, TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    gui_set_parent(text, vsplit);

    // Buttons
    btn_data_t btns[] = { { .txt = "Cancel", .font = DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_EXIT },
        { .txt = "I understand", .font = DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_SET } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}

void make_wallet_erase_pin_options_activity(gui_activity_t** activity_ptr, const char* pinstr)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(pinstr);

    gui_make_activity(activity_ptr, true, "Wallet-Erase PIN");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    char msg[64];
    const int ret = snprintf(msg, sizeof(msg), "\nA wallet-erase PIN is enabled:\n%20s", pinstr);
    JADE_ASSERT(ret > 0 && ret < sizeof(msg));

    gui_view_node_t* text;
    gui_make_text(&text, msg, TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    gui_set_parent(text, vsplit);

    // Buttons
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_WALLET_ERASE_PIN_EXIT },
        { .txt = "Change", .font = DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_SET },
        { .txt = "Disable", .font = DEFAULT_FONT, .ev_id = BTN_WALLET_ERASE_PIN_DISABLE } };
    add_buttons(vsplit, UI_ROW, btns, 3);
}

void make_advanced_options_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Advanced");

    btn_data_t btns[] = { { .txt = "OTP", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP },
        { .txt = "Wallet-Erase PIN", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_WALLET_ERASE_PIN },
        //{ .txt = "Nostr", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_NOSTR },  ??
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_ADVANCED_EXIT },
        { .txt = NULL, .font = JADE_SYMBOLS_16x16_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_otp_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "OTP");

    btn_data_t btns[] = { { .txt = "View OTPs", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_VIEW },
        { .txt = "Scan New OTP QR", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_QR },
        { .txt = "Enter New OTP URI", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_OTP_NEW_KB },
        { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_OTP_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_pinserver_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "PinServer");

    btn_data_t btns[]
        = { { .txt = "View PinServer Settings", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_SHOW },
              { .txt = "Scan Custom PinServer", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_SCAN_QR },
              { .txt = "Reset PinServer Defaults ", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_PINSERVER_RESET },
              { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SETTINGS_PINSERVER_EXIT } };
    add_buttons((*activity_ptr)->root_node, UI_COLUMN, btns, 4);
}

void make_session_screen(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Wallet Session");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 68, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, "\nLogout of current wallet or \nput Jade into sleep mode?", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_parent(text, vsplit);

    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SESSION_EXIT },
        { .txt = "Logout", .font = DEFAULT_FONT, .ev_id = BTN_SESSION_LOGOUT },
        { .txt = "Sleep", .font = DEFAULT_FONT, .ev_id = BTN_SESSION_SLEEP } };
    add_buttons(vsplit, UI_ROW, btns, 3);
}

void make_ble_screen(gui_activity_t** activity_ptr, const char* device_name, gui_view_node_t** ble_status_textbox)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(device_name);
    JADE_INIT_OUT_PPTR(ble_status_textbox);

    gui_make_activity(activity_ptr, true, "Bluetooth");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
        gui_make_button(&btn, TFT_BLACK, BTN_BLE_TOGGLE_ENABLE, NULL);
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
        gui_make_button(&btn, TFT_BLACK, BTN_BLE_RESET_PAIRING, NULL);
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
        gui_make_button(&btn, TFT_BLACK, BTN_BLE_EXIT, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "Exit", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }
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

    gui_activity_t* act = NULL;
    gui_make_activity(&act, true, "Certifications");

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
        btns[0].font = DEFAULT_FONT;
        btns[0].ev_id = BTN_INFO_EXIT;
    }

    // Change last button to 'exit' if on last page
    if (legal_page == MAX_LEGAL_PAGE) {
        btns[1].txt = "Exit";
        btns[1].font = DEFAULT_FONT;
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

void make_legal_screen(gui_activity_t** first_activity_ptr)
{
    JADE_ASSERT(first_activity_ptr);

    // Chain the legal screen activities
    link_activity_t page_act = {};
    linked_activities_info_t act_info = {};

    for (size_t j = 0; j <= MAX_LEGAL_PAGE; j++) {
        make_legal_page(&page_act, j);
        gui_chain_activities(&page_act, &act_info);
    }

    *first_activity_ptr = act_info.first_activity;
}
#endif

void make_device_screen(
    gui_activity_t** activity_ptr, const char* power_status, const char* mac, const char* firmware_version)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(power_status);
    JADE_ASSERT(mac);
    JADE_ASSERT(firmware_version);

    gui_make_activity(activity_ptr, true, "Device");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 21, 21, 21, 37);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
    btn_data_t btns[] = { { .txt = "Legal", .font = DEFAULT_FONT, .ev_id = BTN_INFO_LEGAL },
        { .txt = "Storage", .font = DEFAULT_FONT, .ev_id = BTN_INFO_STORAGE },
        { .txt = "Exit", .font = DEFAULT_FONT, .ev_id = BTN_INFO_EXIT } };
    add_buttons(vsplit, UI_ROW, btns, 3);
#else
    btn_data_t btns[] = { { .txt = "Storage", .font = DEFAULT_FONT, .ev_id = BTN_INFO_STORAGE },
        { .txt = "Exit", .font = DEFAULT_FONT, .ev_id = BTN_INFO_EXIT } };
    add_buttons(vsplit, UI_ROW, btns, 2);
#endif
}

void make_storage_stats_screen(gui_activity_t** activity_ptr, const size_t entries_used, const size_t entries_free)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Storage");

    const size_t entries_total = entries_used + entries_free;
    char buf[16];

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 20, 20, 20, 40);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
        gui_make_button(&btn, TFT_BLACK, BTN_INFO_EXIT, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, row);

        gui_view_node_t* text;
        gui_make_text(&text, "Exit", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }
}
