#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void make_camera_activity(gui_activity_t** activity_ptr, const char* title, const char* btnText,
    gui_view_node_t** image_node, gui_view_node_t** label_node)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(title);
    // btnText is only needed if a 'click' button is wanted
    JADE_ASSERT(image_node);
    JADE_ASSERT(label_node);

    gui_make_activity(activity_ptr, false, NULL);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, (*activity_ptr)->root_node);

    gui_view_node_t* vsplit;
    if (btnText) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 16, 38, 46);
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
    gui_make_text(&text1, title, TFT_WHITE);
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
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 2);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    *label_node = text_status;

    // buttons
    if (btnText) {
        // A 'click' and an 'exit' button
        btn_data_t btns[] = { { .txt = btnText, .font = DEFAULT_FONT, .ev_id = BTN_CAMERA_CLICK },
            { .txt = "Exit", .font = DEFAULT_FONT, .ev_id = BTN_CAMERA_EXIT } };
        add_buttons(vsplit, UI_COLUMN, btns, 2);
    } else {
        // Just an 'exit' button
        btn_data_t btn = { .txt = "Exit", .font = DEFAULT_FONT, .ev_id = BTN_CAMERA_EXIT };
        add_buttons(vsplit, UI_COLUMN, &btn, 1);
    }
}
