#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

#define MAX_DISPLAY_ADDRESS_LEN 192

// also used in sign_tx
gui_activity_t* make_display_address_activities(const char* title, const bool show_one_screen_tick, const char* address,
    const bool default_selection, gui_activity_t** actaddr2)
{
    JADE_ASSERT(address);
    JADE_INIT_OUT_PPTR(actaddr2);

    gui_activity_t* act;

    const size_t addrlen = strlen(address);
    const size_t max_display_len = MAX_DISPLAY_ADDRESS_LEN / 2;
    char buf[1 + max_display_len + 1];

    if (addrlen <= max_display_len) {
        // Just one screen to show address
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_ADDRESS_REJECT },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ADDRESS_ACCEPT } };

        if (!show_one_screen_tick) {
            hdrbtns[1].txt = NULL;
            hdrbtns[1].ev_id = GUI_BUTTON_EVENT_NONE;
        }

        const int ret = snprintf(buf, sizeof(buf), "\n%s", address);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        act = make_show_message_activity(buf, 0, title, hdrbtns, 2, NULL, 0);

        gui_set_activity_initial_selection(
            act, show_one_screen_tick && default_selection ? hdrbtns[1].btn : hdrbtns[0].btn);
    } else {
        // Need two screens to show address
        // First screen 'confirm' button becomes 'next'
        btn_data_t hdrbtns1[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_ADDRESS_REJECT },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_ADDRESS_NEXT } };

        char titlebuf[32];
        int ret = snprintf(titlebuf, sizeof(titlebuf), "%s (1/2)", title);
        JADE_ASSERT(ret > 0 && ret < sizeof(titlebuf));

        ret = snprintf(buf, sizeof(buf), "\n%.*s", max_display_len, address);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        act = make_show_message_activity(buf, 0, titlebuf, hdrbtns1, 2, NULL, 0);

        gui_set_activity_initial_selection(act, hdrbtns1[1].btn);

        // Second screen 'reject' button becomes 'back'
        btn_data_t hdrbtns2[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ADDRESS_ACCEPT } };

        ret = snprintf(titlebuf, sizeof(titlebuf), "%s (2/2)", title);
        JADE_ASSERT(ret > 0 && ret < sizeof(titlebuf));

        ret = snprintf(buf, sizeof(buf), "\n%s", address + max_display_len);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        *actaddr2 = make_show_message_activity(buf, 0, titlebuf, hdrbtns2, 2, NULL, 0);

        gui_set_activity_initial_selection(*actaddr2, default_selection ? hdrbtns2[1].btn : hdrbtns2[0].btn);
    }

    return act;
}

bool show_confirm_address_activity(const char* address, const bool default_selection)
{
    JADE_ASSERT(address);
    // warning_msg is optional

    const bool show_tick = true;
    gui_activity_t* act_addr2 = NULL;
    gui_activity_t* const act_addr1
        = make_display_address_activities("Verify Address", show_tick, address, default_selection, &act_addr2);

    gui_activity_t* act = act_addr1;
    int32_t ev_id;

    while (true) {
        gui_set_current_activity(act);

        // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_ADDRESS_ACCEPT;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_addr1;
                break;

            case BTN_ADDRESS_NEXT:
                act = act_addr2;
                break;

            case BTN_ADDRESS_REJECT:
                return false;

            case BTN_ADDRESS_ACCEPT:
                return true;
            }
        }
    }
}
