#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

void make_confirm_address_activity(gui_activity_t** activity_ptr, const char* address, const char* warning_msg)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(address);

    gui_make_activity(activity_ptr, true, "Confirm Address");
    gui_activity_t* activity = *activity_ptr;
    JADE_ASSERT(activity);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 60, 15, 25);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, activity->root_node);

    // first row, wrapped address (not scrolling)
    gui_view_node_t* text_addr;
    gui_make_text(&text_addr, address, TFT_WHITE);
    gui_set_parent(text_addr, vsplit);
    gui_set_align(text_addr, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_margins(text_addr, GUI_MARGIN_ALL_DIFFERENT, 4, 2, 2, 2);

    // Second row, any warning msg (scrolling)
    if (warning_msg) {
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

    // third row, buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_CANCEL_ADDRESS, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "X", TFT_WHITE);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* black_fill;
    gui_make_fill(&black_fill, TFT_BLACK);
    gui_set_parent(black_fill, hsplit_btn);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_ACCEPT_ADDRESS, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text_font(&textbtn3, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
}
