#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

void make_sign_message_activity(gui_activity_t** activity_ptr, const char* msg_str, const size_t msg_len,
    const bool is_hash, const char* path_as_str)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(msg_str);
    JADE_ASSERT(msg_len < MAX_DISPLAY_MESSAGE_LEN);
    JADE_ASSERT(path_as_str);

    gui_make_activity(activity_ptr, true, "Sign Message");
    gui_activity_t* activity = *activity_ptr;
    JADE_ASSERT(activity);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, activity->root_node);

    // first row, hash value
    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2;
    gui_make_text(&text2, is_hash ? "Hash" : "Message", TFT_WHITE);
    gui_set_parent(text2, hsplit_text2);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text2, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    char display_str[MAX_DISPLAY_MESSAGE_LEN + 8]; // ample
    const int ret = snprintf(display_str, sizeof(display_str), "} %.*s {", msg_len, msg_str);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    gui_view_node_t* text;
    gui_make_text(&text, display_str, TFT_WHITE);
    gui_set_parent(text, hsplit_text2);
    gui_set_align(text, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text, TFT_BLACK);

    // second row, path
    gui_view_node_t* hsplit_text3;
    gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text3, vsplit);

    gui_view_node_t* text3;
    gui_make_text(&text3, "Path", TFT_WHITE);
    gui_set_parent(text3, hsplit_text3);
    gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text3, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    gui_view_node_t* text_path;
    gui_make_text(&text_path, path_as_str, TFT_WHITE);
    gui_set_parent(text_path, hsplit_text3);
    gui_set_align(text_path, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_path, TFT_BLACK);

    // third row, dummy black bg
    gui_view_node_t* dummy_bg;
    gui_make_fill(&dummy_bg, TFT_BLACK);
    gui_set_parent(dummy_bg, vsplit);

    // fourth row, buttons
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
    gui_make_text_font(&textbtn3, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
}
