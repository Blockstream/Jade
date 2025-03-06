#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

gui_activity_t* make_ble_confirmation_activity(const uint32_t numcmp)
{
    char value[8];
    const int ret = snprintf(value, sizeof(value), "%.6lu", numcmp);
    JADE_ASSERT(ret > 0 && ret < sizeof(value));

    const char* message[] = { "Confirm Authentication", "Value:", value };

    btn_data_t ftrbtns[]
        = { { .txt = "Deny", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BLE_DENY, .borders = GUI_BORDER_TOPRIGHT },
              { .txt = "Confirm", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BLE_CONFIRM, .borders = GUI_BORDER_TOPLEFT } };

    return make_show_message_activity(message, 3, "Pair Device", NULL, 0, ftrbtns, 2);
}
#endif // AMALGAMATED_BUILD
