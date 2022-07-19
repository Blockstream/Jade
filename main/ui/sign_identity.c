#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

void make_sign_identity_activity(gui_activity_t** activity_ptr, const char* identity, const size_t identity_len)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(identity);
    JADE_ASSERT(identity_len < MAX_DISPLAY_MESSAGE_LEN);

    gui_make_activity(activity_ptr, true, "Sign Identity");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 10, 56, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
    btn_data_t btns[] = { { .txt = "X", .font = DEFAULT_FONT, .ev_id = BTN_CANCEL_SIGNATURE },
        { .txt = NULL, .font = DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // spacer
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ACCEPT_SIGNATURE } };
    add_buttons(vsplit, UI_ROW, btns, 3);
}
