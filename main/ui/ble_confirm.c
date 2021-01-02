#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void make_ble_confirmation_activity(gui_activity_t** activity_ptr, const uint32_t numcmp)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Confirm BLE Pairing");
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 66, 34);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    char confirm_msg[64];
    const int ret = snprintf(confirm_msg, sizeof(confirm_msg), "Confirm Authentication Value\n\n%24.6d", numcmp);
    JADE_ASSERT(ret > 0 && ret < sizeof(confirm_msg));

    gui_view_node_t* text_status;
    gui_make_text(&text_status, confirm_msg, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, buttons
    gui_view_node_t* hsplit = NULL;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, vsplit);

    // Deny
    gui_view_node_t* btnDeny;
    gui_make_button(&btnDeny, TFT_BLACK, BTN_BLE_DENY, NULL);
    gui_set_margins(btnDeny, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btnDeny, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btnDeny, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btnDeny, hsplit);

    gui_view_node_t* txtDeny;
    gui_make_text(&txtDeny, "Deny", TFT_WHITE);
    gui_set_parent(txtDeny, btnDeny);
    gui_set_align(txtDeny, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Confirm
    gui_view_node_t* btnConfirm;
    gui_make_button(&btnConfirm, TFT_BLACK, BTN_BLE_CONFIRM, NULL);
    gui_set_margins(btnConfirm, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btnConfirm, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btnConfirm, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btnConfirm, hsplit);

    gui_view_node_t* txtConfirm;
    gui_make_text(&txtConfirm, "Confirm", TFT_WHITE);
    gui_set_parent(txtConfirm, btnConfirm);
    gui_set_align(txtConfirm, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
}
