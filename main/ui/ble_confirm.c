#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

gui_activity_t* make_ble_confirmation_activity(const uint32_t numcmp)
{
    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 66, 34);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    char confirm_msg[64];
    const int ret = snprintf(confirm_msg, sizeof(confirm_msg), "Confirm Authentication Value\n\n%24.6ld", numcmp);
    JADE_ASSERT(ret > 0 && ret < sizeof(confirm_msg));

    gui_view_node_t* text_status;
    gui_make_text(&text_status, confirm_msg, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, buttons
    btn_data_t btns[] = { { .txt = "Deny", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BLE_DENY },
        { .txt = "Confirm", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BLE_CONFIRM } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    return act;
}
