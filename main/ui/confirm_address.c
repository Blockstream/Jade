#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

void make_confirm_address_activity(gui_activity_t** activity_ptr, const char* address, const char* warning_msg)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(address);
    JADE_ASSERT(warning_msg);

    gui_make_activity(activity_ptr, true, "Confirm Address");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 60, 15, 25);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, wrapped address (not scrolling)
    gui_view_node_t* text_addr;
    gui_make_text(&text_addr, address, TFT_WHITE);
    gui_set_parent(text_addr, vsplit);
    gui_set_align(text_addr, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_margins(text_addr, GUI_MARGIN_ALL_DIFFERENT, 4, 2, 2, 2);

    // Second row, any warning msg (scrolling)
    if (*warning_msg != '\0') {
        gui_view_node_t* text_warning;
        gui_make_text(&text_warning, warning_msg, TFT_RED);
        gui_set_parent(text_warning, vsplit);
        gui_set_align(text_warning, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text_warning, TFT_BLACK);
    } else {
        gui_view_node_t* row2;
        gui_make_fill(&row2, TFT_BLACK);
        gui_set_parent(row2, vsplit);
    }

    // buttons
    btn_data_t btns[] = { { .txt = "X", .font = DEFAULT_FONT, .ev_id = BTN_CANCEL_ADDRESS },
        { .txt = NULL, .font = DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // spacer
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ACCEPT_ADDRESS } };
    add_buttons(vsplit, UI_ROW, btns, 3);
}
