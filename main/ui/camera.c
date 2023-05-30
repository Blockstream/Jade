#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

gui_activity_t* make_camera_activity(const char* btnText, progress_bar_t* progress_bar, gui_view_node_t** image_node,
    gui_view_node_t** label_node, const bool show_help_btn)
{
    // btnText is only needed if a 'click' button is wanted
    // progress bar is optional
    JADE_INIT_OUT_PPTR(image_node);
    JADE_INIT_OUT_PPTR(label_node);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, act->root_node);

    // LHS
    gui_view_node_t* vsplit;
    if (btnText && progress_bar) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 20, 30, 25, 25);
    } else if (progress_bar || btnText) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 55, 25);
    } else {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 20, 80);
    }
    gui_set_parent(vsplit, hsplit);

    // first row, header, back button
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CAMERA_EXIT, .borders = GUI_BORDER_ALL },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
              { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CAMERA_HELP, .borders = GUI_BORDER_ALL } };

    // Remove help button if not required
    if (!show_help_btn) {
        hdrbtns[2].txt = NULL;
        hdrbtns[2].ev_id = GUI_BUTTON_EVENT_NONE;
    }
    add_buttons(vsplit, UI_ROW, hdrbtns, 3);

    // second row, message
    gui_view_node_t* fill;
    gui_make_fill(&fill, TFT_BLACK);
    gui_set_parent(fill, vsplit);

    gui_make_text(label_node, "Initializing\nthe camera", TFT_WHITE);
    gui_set_parent(*label_node, fill);
    gui_set_padding(*label_node, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, 4);
    gui_set_align(*label_node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // Any progress bar, if applicable
    if (progress_bar) {
        make_progress_bar(vsplit, progress_bar);
    }

    // buttons
    if (btnText) {
        // A 'click' button
        btn_data_t ftrbtn = { .txt = btnText, .font = GUI_DEFAULT_FONT, .ev_id = BTN_CAMERA_CLICK };
        add_buttons(vsplit, UI_ROW, &ftrbtn, 1);
    }

    // RHS
    gui_make_picture(image_node, NULL);
    gui_set_parent(*image_node, hsplit);

    return act;
}
