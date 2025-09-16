#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../ui.h"
#include "../utils/util.h"
#include "jade_assert.h"

static gui_activity_t* make_pinserver_details_activities(const char* urlA, const char* urlB, const char* pubkey_hex,
    const bool initial_confirmation, gui_activity_t** acturl1, gui_activity_t** acturl2, gui_activity_t** actpubkey)
{
    JADE_ASSERT(urlA);
    JADE_ASSERT(urlB);
    JADE_INIT_OUT_PPTR(acturl1);
    JADE_INIT_OUT_PPTR(acturl2);
    JADE_INIT_OUT_PPTR(actpubkey);

    const bool show_help_btn = false;
    const char* const title = initial_confirmation ? "Confirm Oracle" : "Oracle Details";

    // First row, URL
    gui_view_node_t* urlsplit;
    gui_make_hsplit(&urlsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);

    gui_view_node_t* urlnode;
    gui_make_text(&urlnode, "URL:", TFT_WHITE);
    gui_set_align(urlnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(urlnode, urlsplit);

    gui_make_text(&urlnode, urlA, TFT_WHITE);
    gui_set_align(urlnode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(urlnode, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);
    gui_set_parent(urlnode, urlsplit);

    *acturl1 = make_show_single_value_activity("URL", urlA, show_help_btn);

    // Second row, second url
    gui_view_node_t* url2split;
    gui_make_hsplit(&url2split, GUI_SPLIT_RELATIVE, 2, 40, 60);

    gui_view_node_t* url2node;
    gui_make_text(&url2node, "2nd URL:", TFT_WHITE);
    gui_set_align(url2node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(url2node, url2split);

    gui_make_text(&url2node, urlB, TFT_WHITE);
    gui_set_align(url2node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(url2node, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);
    gui_set_parent(url2node, url2split);

    *acturl2 = make_show_single_value_activity("2nd URL", urlB, show_help_btn);

    // Third row, pubkey
    gui_view_node_t* pubkeysplit;
    gui_make_hsplit(&pubkeysplit, GUI_SPLIT_RELATIVE, 2, 40, 60);

    gui_view_node_t* pubkeynode;
    gui_make_text(&pubkeynode, "Pubkey:", TFT_WHITE);
    gui_set_align(pubkeynode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(pubkeynode, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);
    gui_set_parent(pubkeynode, pubkeysplit);

    gui_make_text(&pubkeynode, pubkey_hex, TFT_WHITE);
    gui_set_align(pubkeynode, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(pubkeynode, pubkeysplit);

    *actpubkey = make_show_single_value_activity("Oracle Pubkey", pubkey_hex, show_help_btn);

    // Create buttons/menu
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_PINSERVER_DETAILS_RETAIN_CONFIRM },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // If initial confirmation, also add a 'confirm' button
    // For initial confirmation, the 'back' button is 'discard' rather than 'retain'
    // and we add a 'confirm' button also.
    if (initial_confirmation) {
        hdrbtns[0].ev_id = BTN_PINSERVER_DETAILS_DISCARD_DELETE;

        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;
        hdrbtns[1].ev_id = BTN_PINSERVER_DETAILS_RETAIN_CONFIRM;
    }

    btn_data_t menubtns[] = { { .content = urlsplit, .ev_id = BTN_PINSERVER_DETAILS_URL_A },
        { .content = url2split, .ev_id = BTN_PINSERVER_DETAILS_URL_B },
        { .content = pubkeysplit, .ev_id = BTN_PINSERVER_DETAILS_PUBKEY } };

    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 3);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(urlnode, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(url2node, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(pubkeynode, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

// message details screen for user confirmation
bool show_pinserver_details_activity(
    const char* urlA, const char* urlB, const char* pubkey_hex, const bool initial_confirmation)
{
    // all fields optional

    char display_hex[96];
    if (pubkey_hex) {
        JADE_ASSERT(strlen(pubkey_hex) == 66);
        const int ret
            = snprintf(display_hex, sizeof(display_hex), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s %.*s", 8,
                pubkey_hex, 8, pubkey_hex + 8, 8, pubkey_hex + 16, 8, pubkey_hex + 24, 8, pubkey_hex + 32, 8,
                pubkey_hex + 40, 8, pubkey_hex + 48, 8, pubkey_hex + 56, 2, pubkey_hex + 64);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_hex));
    } else {
        display_hex[0] = '\0';
    }

    gui_activity_t* act_urlA = NULL;
    gui_activity_t* act_urlB = NULL;
    gui_activity_t* act_pubkey = NULL;
    gui_activity_t* act_summary = make_pinserver_details_activities(make_empty_none(urlA), make_empty_none(urlB),
        make_empty_none(display_hex), initial_confirmation, &act_urlA, &act_urlB, &act_pubkey);

    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_PINSERVER_DETAILS_RETAIN_CONFIRM);
        if (ev_id != BTN_EVENT_TIMEOUT) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_summary;
                break;

            case BTN_PINSERVER_DETAILS_URL_A:
                act = act_urlA;
                break;

            case BTN_PINSERVER_DETAILS_URL_B:
                act = act_urlB;
                break;

            case BTN_PINSERVER_DETAILS_PUBKEY:
                act = act_pubkey;
                break;

            case BTN_PINSERVER_DETAILS_DISCARD_DELETE:
                return false;

            case BTN_PINSERVER_DETAILS_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}

static gui_activity_t* make_show_pinserver_certificate_activity(
    const char* cert_hash_hex, const bool initial_confirmation)
{
    JADE_ASSERT(cert_hash_hex);

    const char* const title = initial_confirmation ? "Confirm Oracle" : "Oracle Details";

    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_PINSERVER_DETAILS_RETAIN_CONFIRM },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // If initial confirmation, also add a 'confirm' button
    if (initial_confirmation) {
        hdrbtns[0].ev_id = BTN_PINSERVER_DETAILS_DISCARD_DELETE;

        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;
        hdrbtns[1].ev_id = BTN_PINSERVER_DETAILS_RETAIN_CONFIRM;
    }

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, title, hdrbtns, 2, NULL);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, parent);

    // first row, text
    gui_make_text(&node, "Certificate Hash:", TFT_WHITE);
    gui_set_parent(node, vsplit);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // second row, hash
    gui_make_text(&node, cert_hash_hex, TFT_WHITE);
    gui_set_parent(node, vsplit);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    return act;
}

bool show_pinserver_certificate_activity(const char* cert_hash_hex, const bool initial_confirmation)
{
    // all fields optional

    char display_hex[96];
    if (cert_hash_hex) {
        JADE_ASSERT(strlen(cert_hash_hex) == 64);
        const int ret = snprintf(display_hex, sizeof(display_hex), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s", 8,
            cert_hash_hex, 8, cert_hash_hex + 8, 8, cert_hash_hex + 16, 8, cert_hash_hex + 24, 8, cert_hash_hex + 32, 8,
            cert_hash_hex + 40, 8, cert_hash_hex + 48, 8, cert_hash_hex + 56);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_hex));
    } else {
        display_hex[0] = '\0';
    }

    gui_activity_t* act = make_show_pinserver_certificate_activity(make_empty_none(display_hex), initial_confirmation);
    gui_set_current_activity(act);

    while (true) {
        const int32_t ev_id = gui_activity_wait_button(act, BTN_PINSERVER_DETAILS_RETAIN_CONFIRM);
        if (ev_id != BTN_EVENT_TIMEOUT) {
            switch (ev_id) {
            case BTN_PINSERVER_DETAILS_DISCARD_DELETE:
                return false;

            case BTN_PINSERVER_DETAILS_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}
#endif // AMALGAMATED_BUILD
