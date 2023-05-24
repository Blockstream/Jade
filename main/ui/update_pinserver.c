#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

gui_activity_t* make_show_pinserver_details_activity(
    const char* urlA, const char* urlB, const char* pubkey_hex, const bool confirming_details)
{
    JADE_ASSERT(urlA);
    JADE_ASSERT(urlB);

    char buf[128];

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    // first row, url
    gui_view_node_t* hsplit_text1;
    gui_make_hsplit(&hsplit_text1, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text1, vsplit);

    gui_view_node_t* text1;
    gui_make_text(&text1, "URL", TFT_WHITE);
    gui_set_parent(text1, hsplit_text1);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text1, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    if (urlA[0] == '\0') {
        const int ret = snprintf(buf, sizeof(buf), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", urlA);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_url1;
    gui_make_text(&text_url1, buf, TFT_WHITE);
    gui_set_parent(text_url1, hsplit_text1);
    gui_set_align(text_url1, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_url1, TFT_BLACK);

    // second row, alternative URL
    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2;
    gui_make_text(&text2, "2nd URL", TFT_WHITE);
    gui_set_parent(text2, hsplit_text2);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text2, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    if (urlB[0] == '\0') {
        const int ret = snprintf(buf, sizeof(buf), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", urlB);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_url2;
    gui_make_text(&text_url2, buf, TFT_WHITE);
    gui_set_parent(text_url2, hsplit_text2);
    gui_set_align(text_url2, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_url2, TFT_BLACK);

    // third row, pubkey
    gui_view_node_t* hsplit_text3;
    gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text3, vsplit);

    gui_view_node_t* text3;
    gui_make_text(&text3, "PubKey", TFT_WHITE);
    gui_set_parent(text3, hsplit_text3);
    gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text3, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    if (!pubkey_hex) {
        const int ret = snprintf(buf, sizeof(buf), "<No Change>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", pubkey_hex);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_pubkey;
    gui_make_text(&text_pubkey, buf, TFT_WHITE);
    gui_set_parent(text_pubkey, hsplit_text3);
    gui_set_align(text_pubkey, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_pubkey, TFT_BLACK);

    // fourth row, buttons
    if (confirming_details) {
        // 'Deny' and 'Confirm' buttons
        btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_PINSERVER_DETAILS_DENY },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // spacer
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_PINSERVER_DETAILS_CONFIRM } };
        add_buttons(vsplit, UI_ROW, btns, 3);
    } else {
        // Just a central 'ok' button
        btn_data_t btns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = "Ok", .font = GUI_DEFAULT_FONT, .ev_id = BTN_PINSERVER_DETAILS_CONFIRM },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
        add_buttons(vsplit, UI_ROW, btns, 3);
    }

    return act;
}

gui_activity_t* make_show_pinserver_certificate_activity(const char* cert_hash_hex, const bool confirming_details)
{
    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    // first row, text
    gui_view_node_t* text1;
    const char* message = confirming_details ? "Confirm hash of certificate" : "Additional root certificate";
    gui_make_text(&text1, message, TFT_WHITE);
    gui_set_parent(text1, vsplit);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // second row, hash
    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2;
    gui_make_text(&text2, "Hash", TFT_WHITE);
    gui_set_parent(text2, hsplit_text2);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text2, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    char buf[128];
    if (cert_hash_hex == NULL) {
        const int ret = snprintf(buf, sizeof(buf), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", cert_hash_hex);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_hash;
    gui_make_text(&text_hash, buf, TFT_WHITE);
    gui_set_parent(text_hash, hsplit_text2);
    gui_set_align(text_hash, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_hash, TFT_BLACK);

    // third row, dummy black bg
    gui_view_node_t* dummy_bg3;
    gui_make_fill(&dummy_bg3, TFT_BLACK);
    gui_set_parent(dummy_bg3, vsplit);

    // fourth row, buttons
    if (confirming_details) {
        // 'Deny' and 'Confirm' buttons
        btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_PINSERVER_DETAILS_DENY },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // spacer
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_PINSERVER_DETAILS_CONFIRM } };
        add_buttons(vsplit, UI_ROW, btns, 3);
    } else {
        // Just a central 'ok' button
        btn_data_t btns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = "Ok", .font = GUI_DEFAULT_FONT, .ev_id = BTN_PINSERVER_DETAILS_CONFIRM },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
        add_buttons(vsplit, UI_ROW, btns, 3);
    }

    return act;
}
