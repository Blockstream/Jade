#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

// The button bar along the bottom of the dashboard
static void add_button_bar(gui_view_node_t* parent_node)
{
    // Make the button bar under the passed node, and add all the buttons
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 4, 25, 28, 22, 25);
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
        gui_make_text(&text, "BLE", TFT_WHITE);
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
    gui_make_vsplit(&vsplit, GUI_SPLIT_ABSOLUTE, 2, 75, 36);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text2;
    gui_make_text(&text2, "For setup instructions visit\nblockstream.com/jade", TFT_WHITE);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(text2, GUI_MARGIN_ALL_DIFFERENT, 16, 8, 0, 8);
    gui_set_parent(text2, vsplit);

    add_button_bar(vsplit);
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

void make_ready_screen(gui_activity_t** act_ptr, const char* device_name)
{
    JADE_ASSERT(act_ptr);
    JADE_ASSERT(device_name);

    gui_activity_t* act;
    gui_make_activity(&act, true, device_name);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_ABSOLUTE, 2, 75, 36);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* ready_text;
    gui_make_text(&ready_text, "Ready!", TFT_WHITE);
    gui_set_align(ready_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(ready_text, vsplit);

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
    gui_make_activity(&act, true, "BLE");

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
    // 'Show xpub' button, as well as 'Exit'
    {
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
            gui_make_text(&text, "Show XPUB", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
        }
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
    // No 'Show xpub' button, only 'Exit'
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* fillL;
        gui_make_fill(&fillL, TFT_BLACK);
        gui_set_parent(fillL, hsplit);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_INFO_EXIT, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "Exit", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);

        gui_view_node_t* fillR;
        gui_make_fill(&fillR, TFT_BLACK);
        gui_set_parent(fillR, hsplit);
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
