#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#include "../logo/ce.c"
#include "../logo/fcc.c"
#include "../logo/weee.c"
#endif

#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#include "../logo/telec.c"
#endif

void gen_btns(gui_view_node_t* parent, const size_t num_buttons, const char* msgs[], const uint32_t fonts[],
    const int32_t ev_ids[], gui_view_node_t* out_btns[])
{
    JADE_ASSERT(parent);
    JADE_ASSERT(msgs);
    JADE_ASSERT(ev_ids);
    // NOTE: fonts can be NULL if all GUI_DEFAULT_FONT

    gui_view_node_t* hsplit = NULL;
    switch (num_buttons) {
    case 1:
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        break;
    case 2:
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        break;
    case 3:
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
        break;
    default:
        JADE_ASSERT_MSG(false, "Unsupported number of buttons on screen");
    }

    gui_set_parent(hsplit, parent);

    for (size_t i = 0; i < num_buttons; ++i) {
        gui_view_node_t* btn;
        if (ev_ids[i] == GUI_BUTTON_EVENT_NONE) {
            gui_make_fill(&btn, TFT_BLACK);
        } else {
            gui_make_button(&btn, TFT_BLACK, ev_ids[i], NULL);
        }
        gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);

        if (out_btns) {
            out_btns[i] = btn;
        }

        gui_view_node_t* textbtn;
        gui_make_text(&textbtn, msgs[i], TFT_WHITE);
        if (fonts) {
            gui_set_text_font(textbtn, fonts[i]);
        }
        gui_set_parent(textbtn, btn);
        gui_set_align(textbtn, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }
}

void make_startup_options_screen(gui_activity_t** act_ptr)
{
    JADE_ASSERT(act_ptr);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Advanced Options");

    gui_view_node_t* vsplit;
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
#else
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
#endif
    gui_set_parent(vsplit, act->root_node);

    // Buttons: Reset, One-time wallet, and Continue
    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_SETTINGS_RESET, NULL);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn1, GUI_MARGIN_ALL_DIFFERENT, 4, 25, 0, 25);
    gui_set_parent(btn1, vsplit);

    gui_view_node_t* text1;
    gui_make_text(&text1, "Factory Reset", TFT_WHITE);
    gui_set_align(text1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text1, btn1);

    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_SETTINGS_EMERGENCY_RESTORE, NULL);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn2, GUI_MARGIN_ALL_DIFFERENT, 4, 25, 0, 25);
    gui_set_parent(btn2, vsplit);

    gui_view_node_t* text2;
    gui_make_text(&text2, "Emergency Restore", TFT_WHITE);
    gui_set_align(text2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text2, btn2);

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_SETTINGS_LEGAL, NULL);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn3, GUI_MARGIN_ALL_DIFFERENT, 4, 25, 0, 25);
    gui_set_parent(btn3, vsplit);

    gui_view_node_t* text3;
    gui_make_text(&text3, "Legal", TFT_WHITE);
    gui_set_align(text3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text3, btn3);
#endif

    gui_view_node_t* btn4;
    gui_make_button(&btn4, TFT_BLACK, BTN_SETTINGS_EXIT, NULL);
    gui_set_borders(btn4, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn4, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn4, GUI_MARGIN_ALL_DIFFERENT, 4, 25, 0, 25);
    gui_set_parent(btn4, vsplit);

    gui_view_node_t* text4;
    gui_make_text(&text4, "Exit", TFT_WHITE);
    gui_set_align(text4, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text4, btn4);

    *act_ptr = act;
}

// The button bar along the bottom of the dashboard
static void add_button_bar(gui_view_node_t* parent_node)
{
    // Make the button bar under the passed node, and add all the buttons
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 4, 20, 30, 34, 16);
    gui_set_parent(hsplit, parent_node);

    // sleep btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_SLEEP, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Sleep", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // settings btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Settings", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // ble btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_BLE, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Bluetooth", TFT_WHITE);
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

void make_setup_screen(gui_activity_t** act_ptr, const char* device_name)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(device_name);

    char title[32];
    const int ret = snprintf(title, sizeof(title), "Setup %s", device_name);
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_activity_t* act;
    gui_make_activity(&act, true, title);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text1;
    gui_make_text(&text1, "For setup instructions visit\nblockstream.com/jade", TFT_WHITE);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text1, GUI_MARGIN_ALL_DIFFERENT, 12, 8, 0, 8);
    gui_set_parent(text1, vsplit);

    gui_view_node_t* btn;
    gui_make_button(&btn, TFT_BLACK, BTN_INITIALIZE, NULL);
    gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 15, 50);
    gui_set_parent(btn, vsplit);

    gui_view_node_t* btntext;
    gui_make_text(&btntext, "Initialize", TFT_WHITE);
    gui_set_align(btntext, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(btntext, btn);

    *act_ptr = act;
}

void make_connect_screen(gui_activity_t** act_ptr, const char* device_name)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(device_name);

    char title[32];
    const int ret = snprintf(title, sizeof(title), "Connect %s", device_name);
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_activity_t* act;
    gui_make_activity(&act, true, title);

    gui_view_node_t* text;
    gui_make_text(&text, "Connect Jade to a Blockstream\nGreen companion app", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 24, 8, 0, 8);
    gui_set_parent(text, act->root_node);

    *act_ptr = act;
}

#ifndef CONFIG_ESP32_NO_BLOBS
void make_connection_select_screen(gui_activity_t** act_ptr)
{
    JADE_ASSERT(act_ptr);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Select Connection");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 60, 40);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, "How do you want to connect\nyour Jade to Green?", TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 24, 8, 0, 8);
    gui_set_parent(text, vsplit);

    // Two buttons, USB and BLE
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, vsplit);

    // USB
    gui_view_node_t* usbbtn;
    gui_make_button(&usbbtn, TFT_BLACK, BTN_CONNECT_USB, NULL);
    gui_set_borders(usbbtn, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(usbbtn, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(usbbtn, GUI_MARGIN_ALL_DIFFERENT, 15, 8, 0, 8);
    gui_set_parent(usbbtn, hsplit);

    gui_view_node_t* usbtext;
    gui_make_text(&usbtext, "USB", TFT_WHITE);
    gui_set_align(usbtext, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(usbtext, usbbtn);

    gui_view_node_t* blebtn;
    gui_make_button(&blebtn, TFT_BLACK, BTN_CONNECT_BLE, NULL);
    gui_set_borders(blebtn, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(blebtn, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(blebtn, GUI_MARGIN_ALL_DIFFERENT, 15, 8, 0, 8);
    gui_set_parent(blebtn, hsplit);

    gui_view_node_t* bletext;
    gui_make_text(&bletext, "Bluetooth", TFT_WHITE);
    gui_set_align(bletext, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(bletext, blebtn);

    *act_ptr = act;
}
#endif // CONFIG_ESP32_NO_BLOBS

void make_connect_to_screen(gui_activity_t** act_ptr, const char* device_name, const bool ble)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(device_name);

    char title[32];
    const int ret = snprintf(title, sizeof(title), "Connect %s", device_name);
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_activity_t* act;
    gui_make_activity(&act, true, title);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 60, 40);
    gui_set_parent(vsplit, act->root_node);

    // Text
    const char* message = ble ? "Select your Jade on the Green\ncompanion app to pair it"
                              : "Attach your Jade to a device\nwith Green installed";
    gui_view_node_t* text;
    gui_make_text(&text, message, TFT_WHITE);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 24, 8, 0, 8);
    gui_set_parent(text, vsplit);

#ifndef CONFIG_ESP32_NO_BLOBS
    // Back button
    gui_view_node_t* btn;
    gui_make_button(&btn, TFT_BLACK, BTN_CONNECT_BACK, NULL);
    gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
    gui_set_margins(btn, GUI_MARGIN_ALL_DIFFERENT, 15, 150, 0, 8);
    gui_set_parent(btn, vsplit);

    gui_view_node_t* btntext;
    gui_make_text(&btntext, "=", TFT_WHITE);
    gui_set_text_font(btntext, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(btntext, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(btntext, btn);
#endif

    *act_ptr = act;
}

void make_ready_screen(gui_activity_t** act_ptr, const char* device_name, const char* additional)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(device_name);

    gui_activity_t* act;
    gui_make_activity(&act, true, device_name);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_ABSOLUTE, 3, 40, 35, 36);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* ready_text;
    gui_make_text(&ready_text, "Ready!", TFT_WHITE);
    gui_set_align(ready_text, GUI_ALIGN_CENTER, GUI_ALIGN_BOTTOM);
    gui_set_parent(ready_text, vsplit);

    if (additional) {
        gui_view_node_t* ready_text;
        gui_make_text(&ready_text, additional, TFT_WHITE);
        gui_set_align(ready_text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
        gui_set_parent(ready_text, vsplit);
    } else {
        gui_view_node_t* filler;
        gui_make_fill(&filler, TFT_BLACK);
        gui_set_parent(filler, vsplit);
    }

    add_button_bar(vsplit);
    *act_ptr = act;
}

void make_settings_screen(
    gui_activity_t** act_ptr, gui_view_node_t** orientation_textbox, btn_data_t* timeout_btn, const size_t nBtns)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(orientation_textbox);
    JADE_ASSERT(timeout_btn);
    JADE_ASSERT(nBtns == 6);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Settings");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);
    /*
        {
            gui_view_node_t *hsplit;
            gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
            gui_set_parent(hsplit, vsplit);

            gui_view_node_t *key;
            gui_make_text(&key, "Orientation", TFT_WHITE);
            gui_set_parent(key, hsplit);
            gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

            gui_view_node_t *btn;
            gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS_TOGGLE_ORIENTATION, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t *text;
            gui_make_text(&text, "A", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);

     * orientation_textbox = text;
        }
     */
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Power-off Timeout (mins)", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 6, 16, 16, 16, 16, 18, 18);
        gui_set_parent(hsplit, vsplit);

        for (int i = 0; i < nBtns; ++i) {
            JADE_ASSERT(timeout_btn[i].txt);
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS_TIMEOUT_0 + i, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, timeout_btn[i].txt, TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
            timeout_btn[i].btn = btn;
        }
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        gui_set_parent(hsplit, vsplit);

        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS_RESET, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_RED);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Factory Reset", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        gui_set_parent(hsplit, vsplit);

        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_SETTINGS_EXIT, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Exit", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
    }

    *act_ptr = act;
}

void make_ble_screen(gui_activity_t** act_ptr, const char* device_name, gui_view_node_t** ble_status_textbox)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(ble_status_textbox);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Bluetooth");

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
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        gui_set_parent(hsplit, vsplit);

        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_BLE_EXIT, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Exit", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
    }

    *act_ptr = act;
}

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)

#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#define JADE_FCC_ID "2AWI3BLOCKSTREAMJD2"
#define MAX_LEGAL_PAGE 5
#else
#define JADE_FCC_ID "2AWI3BLOCKSTREAMJD1"
#define MAX_LEGAL_PAGE 4
#endif

static void make_legal_page(gui_activity_t** activity_ptr, int legal_page, gui_view_node_t* out_btns[])
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(out_btns);

    gui_make_activity(activity_ptr, true, "Certifications");
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 63, 37);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
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
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_CENTER);

        gui_view_node_t* subvsplit;
        gui_make_vsplit(&subvsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(subvsplit, hsplit);

        gui_view_node_t* title;
        gui_make_text(&title, "FCC ID", TFT_WHITE);
        gui_set_parent(title, subvsplit);
        gui_set_align(title, GUI_ALIGN_CENTER, GUI_ALIGN_CENTER);

        gui_view_node_t* key;
        gui_make_text(&key, JADE_FCC_ID, TFT_WHITE);
        gui_set_parent(key, subvsplit);
        gui_set_align(key, GUI_ALIGN_CENTER, GUI_ALIGN_CENTER);
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
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_CENTER);
        break;
    }
    case 4: {
        gui_view_node_t* logo_node;
        gui_make_picture(&logo_node, &weee);
        gui_set_parent(logo_node, vsplit);
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_CENTER);
        break;
    }
#if defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    case 5: {
        gui_view_node_t* logo_node;
        gui_make_picture(&logo_node, &telec);
        gui_set_parent(logo_node, vsplit);
        gui_set_align(logo_node, GUI_ALIGN_CENTER, GUI_ALIGN_CENTER);
        break;
    }
#endif
    default: {
        JADE_ASSERT(false);
    }

    } // switch-case

    if (legal_page == 0) {
        // First page, the 'back' button raises 'exit' event
        const char* btn_msg[2] = { "Exit", ">" };
        const uint32_t btn_fonts[2] = { GUI_DEFAULT_FONT, JADE_SYMBOLS_16x16_FONT };
        const int32_t btn_ev_id[2] = { BTN_INFO_EXIT, BTN_LEGAL_NEXT };
        gen_btns(vsplit, 2, btn_msg, btn_fonts, btn_ev_id, out_btns);
    } else if (legal_page == MAX_LEGAL_PAGE) {
        // Last page, the tick button raises 'exit' event
        const char* btn_msg[2] = { "=", "Exit" };
        const uint32_t btn_fonts[2] = { JADE_SYMBOLS_16x16_FONT, GUI_DEFAULT_FONT };
        const int32_t btn_ev_id[2] = { BTN_LEGAL_PREV, BTN_INFO_EXIT };
        gen_btns(vsplit, 2, btn_msg, btn_fonts, btn_ev_id, out_btns);
    } else {
        // Otherwise 'prev' and 'next' events
        const char* btn_msg[2] = { "=", ">" };
        const uint32_t btn_fonts[2] = { JADE_SYMBOLS_16x16_FONT, JADE_SYMBOLS_16x16_FONT };
        const int32_t btn_ev_id[2] = { BTN_LEGAL_PREV, BTN_LEGAL_NEXT };
        gen_btns(vsplit, 2, btn_msg, btn_fonts, btn_ev_id, out_btns);
    }
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 0);

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(*activity_ptr, out_btns[1]);
}

void make_legal_screen(gui_activity_t** first_activity_ptr)
{
    JADE_ASSERT(first_activity_ptr);

    gui_activity_t* prev_act = NULL;
    gui_view_node_t* prev_btn = NULL;

    for (size_t j = 0; j <= MAX_LEGAL_PAGE; j++) {
        gui_view_node_t* btns[2];
        gui_activity_t* this = NULL;

        make_legal_page(&this, j, btns);

        if (prev_act) {
            gui_connect_button_activity(btns[0], prev_act);
            gui_connect_button_activity(prev_btn, this);
        }

        if (!*first_activity_ptr) {
            *first_activity_ptr = this;
        }

        prev_act = this;
        prev_btn = btns[1];
    }
}
#endif

void make_device_screen(
    gui_activity_t** act_ptr, const char* power_status, const char* mac, const char* firmware_version)
{
    JADE_ASSERT(act_ptr);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Device");

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

#ifdef CONFIG_DEBUG_MODE
    // Shows 'XPUB', 'Legal' (only for jade 1 and 1.1) and 'Exit' buttons
    {
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
        gui_set_parent(hsplit, vsplit);

        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_INFO_SHOW_XPUB, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "XPUB", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_INFO_LEGAL, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Legal", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
#else
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_INFO_SHOW_XPUB, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "XPUB", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
#endif
        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_INFO_EXIT, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Exit", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
    }
#else
    // No 'XPUB' button, only 'Legal' (for jade 1 and 1.1) and 'Exit'
    {
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_INFO_LEGAL, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Legal", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
#else
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        gui_set_parent(hsplit, vsplit);
#endif
        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_INFO_EXIT, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);
            gui_view_node_t* text;
            gui_make_text(&text, "Exit", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
    }
#endif // CONFIG_DEBUG_MODE

    *act_ptr = act;
}

#ifdef CONFIG_DEBUG_MODE
void make_show_xpub(gui_activity_t** act_ptr, Icon* qr_icon)
{
    JADE_ASSERT(act_ptr);

    gui_activity_t* act;
    gui_make_activity(&act, false, "NULL");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_ABSOLUTE, 2, 107, GUI_SPLIT_FILL_REMAINING);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* qr_node;
        gui_make_icon(&qr_node, qr_icon, TFT_WHITE);
        gui_set_parent(qr_node, vsplit);
        gui_set_margins(qr_node, GUI_MARGIN_ALL_DIFFERENT, 8, 0, 0, 0);
        gui_set_padding(qr_node, GUI_MARGIN_TWO_VALUES, 0, 70);
    }

    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_INFO_EXIT, NULL);
        gui_set_parent(btn, vsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Click to exit", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    *act_ptr = act;
}
#endif // CONFIG_DEBUG_MODE
