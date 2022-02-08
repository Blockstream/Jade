#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

void make_sign_identity_activity(gui_activity_t** activity_ptr, const char* identity, const size_t identity_len)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(identity);
    JADE_ASSERT(identity_len < MAX_DISPLAY_MESSAGE_LEN);

    gui_make_activity(activity_ptr, true, "Sign Identity");
    gui_activity_t* activity = *activity_ptr;
    JADE_ASSERT(activity);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 10, 56, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, activity->root_node);

    // first row, blank
    gui_view_node_t* dummy_bg;
    gui_make_fill(&dummy_bg, TFT_BLACK);
    gui_set_parent(dummy_bg, vsplit);

    // second row, identity
    char display_str[MAX_DISPLAY_MESSAGE_LEN];
    int ret = snprintf(display_str, sizeof(display_str), "%.*s", identity_len, identity);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    gui_view_node_t* text;
    gui_make_text(&text, display_str, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // third row, buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_CANCEL_SIGNATURE, NULL);
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
    gui_make_button(&btn3, TFT_BLACK, BTN_ACCEPT_SIGNATURE, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text(&textbtn3, "S", TFT_WHITE);
    gui_set_text_font(textbtn3, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
}
