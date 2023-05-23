#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void make_ota_versions_activity(gui_activity_t** activity_ptr, const char* current_version, const char* new_version,
    const char* expected_hash_hexstr, const bool full_fw_hash)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(current_version);
    JADE_ASSERT(new_version);
    JADE_ASSERT(expected_hash_hexstr);

    gui_make_activity(activity_ptr, true, "Firmware Upgrade");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 19, 30);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, current version
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 30, 70);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* label;
        gui_make_text(&label, "Current:", TFT_WHITE);
        gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(label, hsplit);

        gui_view_node_t* version;
        gui_make_text(&version, current_version, TFT_WHITE);
        gui_set_align(version, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(version, hsplit);
    }

    // second row, new version
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 30, 70);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* label;
        gui_make_text(&label, "New:", TFT_WHITE);
        gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(label, hsplit);

        gui_view_node_t* version;
        gui_make_text(&version, new_version, TFT_WHITE);
        gui_set_align(version, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(version, hsplit);
    }

    // third row, hash
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 30, 70);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* label;
        gui_make_text(&label, full_fw_hash ? "Fw Hash:" : "File Hash:", TFT_WHITE);
        gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(label, hsplit);

        JADE_ASSERT(strlen(expected_hash_hexstr) == 64);
        char hashstr[96];
        const int ret = snprintf(hashstr, sizeof(hashstr), "} %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s {", 8,
            expected_hash_hexstr, 8, expected_hash_hexstr + 8, 8, expected_hash_hexstr + 16, 8,
            expected_hash_hexstr + 24, 8, expected_hash_hexstr + 32, 8, expected_hash_hexstr + 40, 8,
            expected_hash_hexstr + 48, 8, expected_hash_hexstr + 56);
        JADE_ASSERT(ret > 0 && ret < sizeof(hashstr));

        gui_view_node_t* hash;
        gui_make_text(&hash, hashstr, TFT_WHITE);
        gui_set_align(hash, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(hash, hsplit);
        gui_set_text_scroll(hash, TFT_BLACK);
    }

    // fourth row, text
    {
        gui_view_node_t* msg;
        gui_make_text(&msg, "Continue with Update ?", TFT_WHITE);
        gui_set_align(msg, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(msg, vsplit);
    }

    // fifth row, buttons
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 30, 30, 40);
    gui_set_parent(hsplit, vsplit);

    // cancel btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_CANCEL_OTA, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "X", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // accept btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_ACCEPT_OTA, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text_font(&text, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }

    // view-hash btn
    {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_OTA_VIEW_FW_HASH, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, hsplit);
        gui_view_node_t* text;
        gui_make_text(&text, "View Hash", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
    }
}

void make_show_ota_hash_activity(
    gui_activity_t** activity_ptr, const char* expected_hash_hexstr, const bool full_fw_hash)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(expected_hash_hexstr);

    gui_make_activity(activity_ptr, true, "Confirm Hash");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 50, 30);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, label
    {
        const char* label_text = full_fw_hash ? "New Firmware Hash:" : "Uploaded File Hash:";
        gui_view_node_t* label;
        gui_make_text(&label, label_text, TFT_WHITE);
        gui_set_padding(label, GUI_MARGIN_TWO_VALUES, 4, 4);
        gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(label, vsplit);
    }

    // second row, hash
    {
        JADE_ASSERT(strlen(expected_hash_hexstr) == 64);
        char hashstr[96];
        const int ret = snprintf(hashstr, sizeof(hashstr), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s", 8,
            expected_hash_hexstr, 8, expected_hash_hexstr + 8, 8, expected_hash_hexstr + 16, 8,
            expected_hash_hexstr + 24, 8, expected_hash_hexstr + 32, 8, expected_hash_hexstr + 40, 8,
            expected_hash_hexstr + 48, 8, expected_hash_hexstr + 56);
        JADE_ASSERT(ret > 0 && ret < sizeof(hashstr));

        gui_view_node_t* hash;
        gui_make_text(&hash, hashstr, TFT_WHITE);
        gui_set_padding(hash, GUI_MARGIN_TWO_VALUES, 4, 4);
        gui_set_align(hash, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        gui_set_parent(hash, vsplit);
    }

    // third row, buttons
    btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_CANCEL_OTA },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_OTA_HASH_CONFIRMED } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}
