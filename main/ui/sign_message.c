#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

static gui_activity_t* make_sign_message_activities(const char* msgtxt, const char* hashhex, const char* pathstr,
    gui_activity_t** actmessage1, gui_activity_t** actmessage2, gui_activity_t** acthash, gui_activity_t** actpath)
{
    JADE_ASSERT(msgtxt);
    JADE_ASSERT(hashhex);
    JADE_ASSERT(pathstr);
    JADE_INIT_OUT_PPTR(actmessage1);
    JADE_INIT_OUT_PPTR(actmessage2);
    JADE_INIT_OUT_PPTR(acthash);
    JADE_INIT_OUT_PPTR(actpath);

    const bool show_help_btn = false;

    // First row, msgtxt
    gui_view_node_t* msgsplit;
    gui_make_hsplit(&msgsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);

    gui_view_node_t* msgnode;
    gui_make_text(&msgnode, "Message:", TFT_WHITE);
    gui_set_align(msgnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(msgnode, msgsplit);

    gui_make_text(&msgnode, msgtxt, TFT_WHITE);
    gui_set_align(msgnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(msgnode, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);
    gui_set_parent(msgnode, msgsplit);

    // NOTE: maybe two value drilldown screens
    const size_t msgtxt_len = strlen(msgtxt);
    JADE_ASSERT(msgtxt_len <= MAX_DISPLAY_MESSAGE_LEN);
    const size_t max_display_len = MAX_DISPLAY_MESSAGE_LEN / 2;
    char buf[1 + max_display_len + 1];
    const char* message[] = { buf };

    if (msgtxt_len <= max_display_len) {
        // Just the one message screen with a tick/accept button
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_SIGNMSG_ACCEPT } };

        const int ret = snprintf(buf, sizeof(buf), "\n%s", msgtxt);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        *actmessage1 = make_show_message_activity(message, 1, "Message", hdrbtns, 2, NULL, 0);
        *actmessage2 = NULL;
    } else {
        // Two message screens
        // First message screen needs a 'next' button
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNMSG_NEXT } };

        int ret = snprintf(buf, sizeof(buf), "\n%.*s", max_display_len, msgtxt);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
        *actmessage1 = make_show_message_activity(message, 1, "Message (1/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actmessage1, hdrbtns[1].btn);

        // Second message screen has a tick button
        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;

        ret = snprintf(buf, sizeof(buf), "\n%s", msgtxt + max_display_len);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
        *actmessage2 = make_show_message_activity(message, 1, "Message (2/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actmessage2, hdrbtns[1].btn);
    }

    // Second row, hash
    gui_view_node_t* hashsplit;
    gui_make_hsplit(&hashsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);

    gui_view_node_t* hashnode;
    gui_make_text(&hashnode, "Hash:", TFT_WHITE);
    gui_set_align(hashnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(hashnode, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);
    gui_set_parent(hashnode, hashsplit);

    gui_make_text(&hashnode, hashhex, TFT_WHITE);
    gui_set_align(hashnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(hashnode, hashsplit);

    *acthash = make_show_single_value_activity("Hash", hashhex, show_help_btn);

    // Third row, path
    gui_view_node_t* pathsplit;
    gui_make_hsplit(&pathsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);

    gui_view_node_t* pathnode;
    gui_make_text(&pathnode, "Path:", TFT_WHITE);
    gui_set_align(pathnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(pathnode, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);
    gui_set_parent(pathnode, pathsplit);

    gui_make_text(&pathnode, pathstr, TFT_WHITE);
    gui_set_align(pathnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(pathnode, pathsplit);

    *actpath = make_show_single_value_activity("Path", pathstr, show_help_btn);

    // Create buttons/menu
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNMSG_REJECT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_SIGNMSG_ACCEPT } };

    btn_data_t menubtns[] = { { .content = msgsplit, .ev_id = BTN_SIGNMSG_MSG },
        { .content = hashsplit, .ev_id = BTN_SIGNMSG_HASH }, { .content = pathsplit, .ev_id = BTN_SIGNMSG_PATH } };

    gui_activity_t* const act = make_menu_activity("Sign Message", hdrbtns, 2, menubtns, 3);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(msgnode, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(hashnode, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(pathnode, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

// message details screen for user confirmation
bool show_sign_message_activity(const char* message, const char* hashhex, const char* pathstr)
{
    JADE_ASSERT(message);
    JADE_ASSERT(hashhex);
    JADE_ASSERT(pathstr);

    // Break up hash string into groups of 8 chars
    char hashstr[96];
    JADE_ASSERT(strlen(hashhex) == 64);
    const int ret = snprintf(hashstr, sizeof(hashstr), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s", 8, hashhex, 8,
        hashhex + 8, 8, hashhex + 16, 8, hashhex + 24, 8, hashhex + 32, 8, hashhex + 40, 8, hashhex + 48, 8,
        hashhex + 56);
    JADE_ASSERT(ret > 0 && ret < sizeof(hashstr));

    gui_activity_t* act_message1 = NULL;
    gui_activity_t* act_message2 = NULL;
    gui_activity_t* act_hash = NULL;
    gui_activity_t* act_path = NULL;
    gui_activity_t* act_summary
        = make_sign_message_activities(message, hashstr, pathstr, &act_message1, &act_message2, &act_hash, &act_path);

    gui_activity_t* act = act_summary;
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
        ev_id = BTN_SIGNMSG_ACCEPT;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = (act == act_message2) ? act_message1 : act_summary;
                break;

            case BTN_SIGNMSG_MSG:
                act = act_message1;
                break;

            case BTN_SIGNMSG_HASH:
                act = act_hash;
                break;

            case BTN_SIGNMSG_PATH:
                act = act_path;
                break;

            case BTN_SIGNMSG_NEXT:
                act = (act == act_message1) ? act_message2 : act_summary;
                break;

            case BTN_SIGNMSG_REJECT:
                return false;

            case BTN_SIGNMSG_ACCEPT:
                return true;
            }
        }
    }
}
