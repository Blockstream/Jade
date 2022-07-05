#include <string.h>

#include "../button_events.h"
#include "../gui.h"
#include "../jade_assert.h"

void make_camera_activity(
    gui_activity_t** activity_ptr, const char* btnText, gui_view_node_t** image_node, gui_view_node_t** label_node)
{
    JADE_ASSERT(activity_ptr);
    // btnText is only needed if a 'click' button is wanted
    JADE_ASSERT(image_node);
    JADE_ASSERT(label_node);

    gui_make_activity(activity_ptr, false, NULL);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, (*activity_ptr)->root_node);

    gui_view_node_t* vsplit;
    if (btnText) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 38, 23, 23);
    } else {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 16, 54, 30);
    }
    gui_set_parent(vsplit, hsplit);

    gui_view_node_t* camera_fill;
    gui_make_picture(&camera_fill, NULL);
    gui_set_parent(camera_fill, hsplit);
    *image_node = camera_fill;

    // first row, header
    gui_view_node_t* text1;
    gui_make_text(&text1, "Camera", TFT_WHITE);
    gui_set_parent(text1, vsplit);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text1, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    // second row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* text_status;
    gui_make_text(&text_status, "Initializing the\ncamera...", TFT_WHITE);
    gui_set_parent(text_status, text_bg);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    *label_node = text_status;

    // third row: click button if wanted
    if (btnText) {
        gui_view_node_t* btn1;
        gui_make_button(&btn1, TFT_BLACK, BTN_CAMERA_CLICK, NULL);
        gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
        gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn1, vsplit);

        gui_view_node_t* btn1_text;
        gui_make_text(&btn1_text, btnText, TFT_WHITE);
        gui_set_align(btn1_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(btn1_text, btn1);
    }

    // last row: exit button
    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_CAMERA_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, vsplit);

    gui_view_node_t* btn2_text;
    gui_make_text(&btn2_text, "Exit", TFT_WHITE);
    gui_set_align(btn2_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(btn2_text, btn2);
}