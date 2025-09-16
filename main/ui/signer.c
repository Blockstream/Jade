#ifndef AMALGAMATED_BUILD

#include "../signer.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../ui.h"
#include "../utils/event.h"
#include "../wallet.h"

static gui_activity_t* make_signer_activities(const signer_t* signer, const size_t signer_number,
    const size_t num_signers, const bool is_this_signer, gui_activity_t** actfingerprint,
    gui_activity_t** actderivation, gui_activity_t** actxpub1, gui_activity_t** actxpub2, gui_activity_t** actpath)
{
    JADE_ASSERT(signer);
    JADE_ASSERT(signer_number > 0);
    JADE_ASSERT(signer_number <= num_signers);
    JADE_INIT_OUT_PPTR(actfingerprint);
    JADE_INIT_OUT_PPTR(actderivation);
    JADE_INIT_OUT_PPTR(actxpub1);
    JADE_INIT_OUT_PPTR(actxpub2);
    JADE_INIT_OUT_PPTR(actpath);

    const bool show_help_btn = false;
    char display_str[MAX_PATH_STR_LEN(MAX_PATH_LEN)];

    // First row, fingerprint
    gui_view_node_t* splitfingerprint;
    gui_make_hsplit(&splitfingerprint, GUI_SPLIT_RELATIVE, 2, 55, 45);

    gui_view_node_t* fingerprint;
    gui_make_text(&fingerprint, "Fingerprint: ", TFT_WHITE);
    gui_set_align(fingerprint, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(fingerprint, splitfingerprint);

    char* fingerprint_hex;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(signer->fingerprint, sizeof(signer->fingerprint), &fingerprint_hex));
    gui_make_text(&fingerprint, fingerprint_hex, TFT_WHITE);
    gui_set_align(fingerprint, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(fingerprint, splitfingerprint);

    *actfingerprint = make_show_single_value_activity("Fingerprint", fingerprint_hex, show_help_btn);
    JADE_WALLY_VERIFY(wally_free_string(fingerprint_hex));

    // Second row, type
    gui_view_node_t* splitderivation;
    gui_make_hsplit(&splitderivation, GUI_SPLIT_RELATIVE, 2, 55, 45);

    gui_view_node_t* derivation;
    gui_make_text(&derivation, "Derivation: ", TFT_WHITE);
    gui_set_align(derivation, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(derivation, splitderivation);

    if (signer->derivation_len == 0) {
        strcpy(display_str, "<None>");
    } else if (!wallet_bip32_path_as_str(
                   signer->derivation, signer->derivation_len, display_str, sizeof(display_str))) {
        strcpy(display_str, "[too long]");
    }
    gui_make_text(&derivation, display_str, TFT_WHITE);
    gui_set_align(derivation, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(derivation, splitderivation);

    *actderivation = make_show_single_value_activity("Derivation", display_str, show_help_btn);

    // Third row, xpub
    gui_view_node_t* splitxpub;
    gui_make_hsplit(&splitxpub, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* xpub;
    gui_make_text(&xpub, "Xpub: ", TFT_WHITE);
    gui_set_align(xpub, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(xpub, splitxpub);

    gui_make_text(&xpub, signer->xpub, TFT_WHITE);
    gui_set_align(xpub, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(xpub, splitxpub);

    // NOTE: two xpub drilldown screens
    {
        const size_t display_len = signer->xpub_len / 2;
        JADE_ASSERT(display_len + 2 <= sizeof(display_str));
        const char* message[] = { display_str };

        // First screen needs a 'next' button
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNER_XPUB_NEXT } };

        int ret = snprintf(display_str, sizeof(display_str), "\n%.*s", display_len, signer->xpub);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

        *actxpub1 = make_show_message_activity(message, 1, "Xpub (1/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(hdrbtns[1].btn);

        // Second message screen has a tick button
        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;

        ret = snprintf(display_str, sizeof(display_str), "\n%s", signer->xpub + display_len);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

        *actxpub2 = make_show_message_activity(message, 1, "Xpub (2/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(hdrbtns[1].btn);
    }

    // Fourth row, path
    gui_view_node_t* splitpath;
    gui_make_hsplit(&splitpath, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* path;
    gui_make_text(&path, "Path: ", TFT_WHITE);
    gui_set_align(path, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(path, splitpath);

    if (signer->path_len == 0) {
        strcpy(display_str, "<None>");
    } else if (signer->path_is_string) {
        JADE_ASSERT(signer->path_len < sizeof(display_str));
        strcpy(display_str, signer->path_str);
    } else if (!wallet_bip32_path_as_str(signer->path, signer->path_len, display_str, sizeof(display_str))) {
        strcpy(display_str, "[too long]");
    }
    gui_make_text(&path, display_str, TFT_WHITE);
    gui_set_align(path, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(path, splitpath);

    *actpath = make_show_single_value_activity("Path", display_str, show_help_btn);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNER_PREV },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNER_NEXT } };

    btn_data_t menubtns[] = { { .content = splitfingerprint, .ev_id = BTN_SIGNER_FINGERPRINT },
        { .content = splitderivation, .ev_id = BTN_SIGNER_DERIVATION },
        { .content = splitxpub, .ev_id = BTN_SIGNER_XPUB }, { .content = splitpath, .ev_id = BTN_SIGNER_PATH } };

    char title[24];
    const int ret
        = snprintf(title, sizeof(title), "Signer %d/%d%s", signer_number, num_signers, is_this_signer ? " *" : "");
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 4);

    // Set the intially selected item to the 'Next' button
    gui_set_activity_initial_selection(hdrbtns[1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(fingerprint, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(derivation, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(xpub, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(path, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

bool show_signer_activity(
    const signer_t* signer, const size_t signer_number, const size_t num_signers, const bool is_this_signer)
{
    JADE_ASSERT(signer);
    JADE_ASSERT(signer_number > 0);
    JADE_ASSERT(signer_number <= num_signers);

    gui_activity_t* act_fingerprint = NULL;
    gui_activity_t* act_derivation = NULL;
    gui_activity_t* act_xpub1 = NULL;
    gui_activity_t* act_xpub2 = NULL;
    gui_activity_t* act_path = NULL;
    gui_activity_t* act_summary = make_signer_activities(signer, signer_number, num_signers, is_this_signer,
        &act_fingerprint, &act_derivation, &act_xpub1, &act_xpub2, &act_path);
    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_SIGNER_NEXT);
        if (ev_id != BTN_EVENT_TIMEOUT) {
            switch (ev_id) {
            case BTN_BACK:
                act = (act == act_xpub2) ? act_xpub1 : act_summary;
                break;

            case BTN_SIGNER_FINGERPRINT:
                act = act_fingerprint;
                break;

            case BTN_SIGNER_DERIVATION:
                act = act_derivation;
                break;

            case BTN_SIGNER_PATH:
                act = act_path;
                break;

            case BTN_SIGNER_XPUB:
                act = act_xpub1;
                break;

            case BTN_SIGNER_XPUB_NEXT:
                act = (act == act_xpub1) ? act_xpub2 : act_summary;
                break;

            case BTN_SIGNER_PREV:
                return false;

            case BTN_SIGNER_NEXT:
                return true;
            }
        }
    }
}
#endif // AMALGAMATED_BUILD
