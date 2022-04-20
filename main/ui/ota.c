#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void make_ota_versions_activity(gui_activity_t** activity_ptr, const char* current_version, const char* new_version,
    const char* expected_hash_hexstr)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(current_version);
    JADE_ASSERT(new_version);
    // TODO: add assert here when hash made mandatory

    gui_make_activity(activity_ptr, true, "Firmware Upgrade");
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 19, 19, 19, 19, 24);
    gui_set_parent(vsplit, act->root_node);

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
    if (expected_hash_hexstr) {
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
    } else {
        // TODO: remove this option when hash made mandatory
        gui_view_node_t* filler;
        gui_make_fill(&filler, TFT_BLACK);
        gui_set_parent(filler, vsplit);
    }

    // fourth row, text
    {
        gui_view_node_t* msg;
        gui_make_text(&msg, "Continue with Update ?", TFT_WHITE);
        gui_set_align(msg, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(msg, vsplit);
    }

    // fifth row, buttons
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        // Cancel
        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_CANCEL_OTA, NULL);
            gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);

            gui_view_node_t* textbtn;
            gui_make_text(&textbtn, "X", TFT_WHITE);
            gui_set_parent(textbtn, btn);
            gui_set_align(textbtn, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }

        // Ok
        {
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, BTN_ACCEPT_OTA, NULL);
            gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn, hsplit);

            gui_view_node_t* textbtn;
            gui_make_text_font(&textbtn, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
            gui_set_parent(textbtn, btn);
            gui_set_align(textbtn, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }
    }
}
