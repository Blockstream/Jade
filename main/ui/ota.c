#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void make_ota_versions_activity(gui_activity_t** activity_ptr, const char* current_version, const char* new_version,
    const char* expected_hash_hexstr)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(current_version);
    JADE_ASSERT(new_version);
    JADE_ASSERT(expected_hash_hexstr);

    gui_make_activity(activity_ptr, true, "Firmware Upgrade");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 19, 19, 19, 19, 24);
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
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit, vsplit);

    gui_view_node_t* label;
    gui_make_text(&label, "Hash:", TFT_WHITE);
    gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(label, hsplit);

    char hashstr[96];
    const int ret = snprintf(hashstr, sizeof(hashstr), "} %s {", expected_hash_hexstr);
    JADE_ASSERT(ret > 0 && ret < sizeof(hashstr));

    gui_view_node_t* hash;
    gui_make_text(&hash, hashstr, TFT_WHITE);
    gui_set_align(hash, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(hash, hsplit);
    gui_set_text_scroll(hash, TFT_BLACK);

    // fourth row, text
    {
        gui_view_node_t* msg;
        gui_make_text(&msg, "Continue with Update ?", TFT_WHITE);
        gui_set_align(msg, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(msg, vsplit);
    }

    // fifth row, buttons
    btn_data_t btns[] = { { .txt = "X", .font = DEFAULT_FONT, .ev_id = BTN_CANCEL_OTA },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ACCEPT_OTA } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}
