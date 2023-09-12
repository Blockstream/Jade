#include <inttypes.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../multisig.h"
#include "../ui.h"
#include "../utils/event.h"
#include "../utils/util.h"

#include <sodium/utils.h>

bool wallet_bip32_path_as_str(const uint32_t* parts, size_t num_parts, char* output, const size_t output_len);

static gui_activity_t* make_view_multisig_activities(const char* multisig_name, const bool initial_confirmation,
    const bool is_valid, const bool is_sorted, const size_t threshold, const size_t num_signers,
    const char* master_blinding_key_hex, gui_activity_t** actname, gui_activity_t** acttype, gui_activity_t** actsorted,
    gui_activity_t** actblindingkey)
{
    JADE_ASSERT(multisig_name);
    // master blinding key is optional
    JADE_INIT_OUT_PPTR(actname);
    JADE_INIT_OUT_PPTR(acttype);
    JADE_INIT_OUT_PPTR(actsorted);
    JADE_INIT_OUT_PPTR(actblindingkey);

    // initial confirmations can't be invalid
    JADE_ASSERT(!initial_confirmation || is_valid);

    const bool show_help_btn = false;
    char display_str[2 * MULTISIG_MASTER_BLINDING_KEY_SIZE + 1];

    // First row, name
    gui_view_node_t* splitname;
    gui_make_hsplit(&splitname, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* name;
    gui_make_text(&name, "Name: ", TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    gui_make_text(&name, multisig_name, TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    *actname = make_show_single_value_activity("Wallet Name", multisig_name, show_help_btn);

    // If not valid, no details, just message
    if (!is_valid) {
        // Create 'name' button and warning
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MULTISIG_RETAIN_CONFIRM },
            { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_MULTISIG_DISCARD_DELETE } };

        btn_data_t menubtns[] = { { .content = splitname, .ev_id = BTN_MULTISIG_NAME },
            { .txt = "Not valid for", .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = "current wallet", .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

        gui_activity_t* const act = make_menu_activity("Registered Wallet", hdrbtns, 2, menubtns, 4);

        // NOTE: can only set scrolling *after* gui tree created
        gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
        return act;
    }

    // Second row, type
    gui_view_node_t* splittype;
    gui_make_hsplit(&splittype, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* type;
    gui_make_text(&type, "Type: ", TFT_WHITE);
    gui_set_align(type, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(type, splittype);

    int ret = snprintf(display_str, sizeof(display_str), "%uof%u", threshold, num_signers);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    gui_make_text(&type, display_str, TFT_WHITE);
    gui_set_align(type, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(type, splittype);

    *acttype = make_show_single_value_activity("Type", display_str, show_help_btn);

    // Third row, sorted flag
    gui_view_node_t* splitsorted;
    gui_make_hsplit(&splitsorted, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* sorted;
    gui_make_text(&sorted, "Sorted: ", TFT_WHITE);
    gui_set_align(sorted, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(sorted, splitsorted);

    gui_make_text(&sorted, is_sorted ? "Yes" : "No", TFT_WHITE);
    gui_set_align(sorted, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(sorted, splitsorted);

    *actsorted = make_show_single_value_activity("Sorted", is_sorted ? "Yes" : "No", show_help_btn);

    // Forth row, blinding key
    gui_view_node_t* splitblindingkey;
    gui_make_hsplit(&splitblindingkey, GUI_SPLIT_RELATIVE, 2, 55, 45);

    gui_view_node_t* blindingkey;
    gui_make_text(&blindingkey, "Blinding Key: ", TFT_WHITE);
    gui_set_align(blindingkey, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(blindingkey, splitblindingkey);

    gui_make_text(&blindingkey, master_blinding_key_hex, TFT_WHITE);
    gui_set_align(blindingkey, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(blindingkey, splitblindingkey);

    *actblindingkey = make_show_single_value_activity("Blinding Key", master_blinding_key_hex, show_help_btn);

    // Buttons - Delete and Next
    btn_data_t hdrbtns[] = { { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_MULTISIG_DISCARD_DELETE },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MULTISIG_RETAIN_CONFIRM } };

    btn_data_t menubtns[] = { { .content = splitname, .ev_id = BTN_MULTISIG_NAME },
        { .content = splittype, .ev_id = BTN_MULTISIG_TYPE }, { .content = splitsorted, .ev_id = BTN_MULTISIG_SORTED },
        { .content = splitblindingkey, .ev_id = BTN_MULTISIG_BLINDINGKEY } };

    const char* title = initial_confirmation ? "Register Multisig" : "Registered Wallet";
    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 4);

    // Set the intially selected item to the 'Next' button
    gui_set_activity_initial_selection(act, hdrbtns[1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
    // gui_set_text_scroll_selected(type, true, TFT_BLACK, gui_get_highlight_color());
    // gui_set_text_scroll_selected(sorted, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(blindingkey, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

// multisig details screen for viewing or confirmation
// returns true if we are to store/retain this record, false if we are to discard/delete the record
static bool show_view_multisig_activity(const char* multisig_name, const bool initial_confirmation, const bool is_valid,
    const bool is_sorted, const size_t threshold, const size_t num_signers, const char* master_blinding_key_hex)
{
    JADE_ASSERT(multisig_name);

    // Break up key string into groups of 8 chars
    char blindingkeystr[96];
    if (master_blinding_key_hex) {
        JADE_ASSERT(strlen(master_blinding_key_hex) == 64);
        const int ret
            = snprintf(blindingkeystr, sizeof(blindingkeystr), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s", 8,
                master_blinding_key_hex, 8, master_blinding_key_hex + 8, 8, master_blinding_key_hex + 16, 8,
                master_blinding_key_hex + 24, 8, master_blinding_key_hex + 32, 8, master_blinding_key_hex + 40, 8,
                master_blinding_key_hex + 48, 8, master_blinding_key_hex + 56);
        JADE_ASSERT(ret > 0 && ret < sizeof(blindingkeystr));
    } else {
        blindingkeystr[0] = '\0';
    }

    gui_activity_t* act_name = NULL;
    gui_activity_t* act_type = NULL;
    gui_activity_t* act_sorted = NULL;
    gui_activity_t* act_blindingkey = NULL;
    gui_activity_t* act_summary
        = make_view_multisig_activities(multisig_name, initial_confirmation, is_valid, is_sorted, threshold,
            num_signers, make_empty_none(blindingkeystr), &act_name, &act_type, &act_sorted, &act_blindingkey);
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
        ev_id = BTN_MULTISIG_RETAIN_CONFIRM;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_summary;
                break;

            case BTN_MULTISIG_NAME:
                act = act_name;
                break;

            case BTN_MULTISIG_TYPE:
                act = act_type;
                break;

            case BTN_MULTISIG_SORTED:
                act = act_sorted;
                break;

            case BTN_MULTISIG_BLINDINGKEY:
                act = act_blindingkey;
                break;

            case BTN_MULTISIG_DISCARD_DELETE:
                return false;

            case BTN_MULTISIG_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}

static gui_activity_t* make_multisig_signer_activities(const signer_t* signer, const size_t signer_number,
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

        // First screen needs a 'next' button
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MULTISIG_SIGNER_XPUB_NEXT } };

        int ret = snprintf(display_str, sizeof(display_str), "\n%.*s", display_len, signer->xpub);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actxpub1 = make_show_message_activity(display_str, 0, "Xpub (1/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actxpub1, hdrbtns[1].btn);

        // Second message screen has a tick button
        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;

        ret = snprintf(display_str, sizeof(display_str), "\n%s", signer->xpub + display_len);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actxpub2 = make_show_message_activity(display_str, 0, "Xpub (2/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actxpub2, hdrbtns[1].btn);
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
    } else if (!wallet_bip32_path_as_str(signer->path, signer->path_len, display_str, sizeof(display_str))) {
        strcpy(display_str, "[too long]");
    }
    gui_make_text(&path, display_str, TFT_WHITE);
    gui_set_align(path, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(path, splitpath);

    *actpath = make_show_single_value_activity("Path", display_str, show_help_btn);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MULTISIG_PREV },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MULTISIG_NEXT } };

    btn_data_t menubtns[] = { { .content = splitfingerprint, .ev_id = BTN_MULTISIG_SIGNER_FINGERPRINT },
        { .content = splitderivation, .ev_id = BTN_MULTISIG_SIGNER_DERIVATION },
        { .content = splitxpub, .ev_id = BTN_MULTISIG_SIGNER_XPUB },
        { .content = splitpath, .ev_id = BTN_MULTISIG_SIGNER_PATH } };

    char title[24];
    const int ret
        = snprintf(title, sizeof(title), "Signer %d/%d%s", signer_number, num_signers, is_this_signer ? " *" : "");
    JADE_ASSERT(ret > 0 && ret < sizeof(title));

    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 4);

    // Set the intially selected item to the 'Next' button
    gui_set_activity_initial_selection(act, hdrbtns[1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(fingerprint, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(derivation, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(xpub, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(path, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

static bool show_multisig_signer_activity(
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
    gui_activity_t* act_summary = make_multisig_signer_activities(signer, signer_number, num_signers, is_this_signer,
        &act_fingerprint, &act_derivation, &act_xpub1, &act_xpub2, &act_path);
    gui_activity_t* act = act_summary;
    int32_t ev_id;

    while (true) {
        gui_set_current_activity(act);

        // In a debug unattended ci build, assume 'next' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_MULTISIG_NEXT;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = (act == act_xpub2) ? act_xpub1 : act_summary;
                break;

            case BTN_MULTISIG_SIGNER_FINGERPRINT:
                act = act_fingerprint;
                break;

            case BTN_MULTISIG_SIGNER_DERIVATION:
                act = act_derivation;
                break;

            case BTN_MULTISIG_SIGNER_PATH:
                act = act_path;
                break;

            case BTN_MULTISIG_SIGNER_XPUB:
                act = act_xpub1;
                break;

            case BTN_MULTISIG_SIGNER_XPUB_NEXT:
                act = (act == act_xpub1) ? act_xpub2 : act_summary;
                break;

            case BTN_MULTISIG_PREV:
                return false;

            case BTN_MULTISIG_NEXT:
                return true;
            }
        }
    }
}

static gui_activity_t* make_final_multisig_summary_activities(const char* multisig_name, const size_t threshold,
    const size_t num_signers, const size_t num_signer_details, const bool initial_confirmation, const bool overwriting,
    gui_activity_t** actname, gui_activity_t** acttype)
{
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(threshold <= num_signers);
    JADE_ASSERT(!overwriting || initial_confirmation);
    JADE_ASSERT(num_signer_details <= num_signers);
    JADE_ASSERT(num_signer_details == num_signers || !initial_confirmation);
    JADE_INIT_OUT_PPTR(actname);
    JADE_INIT_OUT_PPTR(acttype);

    const bool show_help_btn = false;

    // First row, name
    gui_view_node_t* splitname;
    gui_make_hsplit(&splitname, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* name;
    gui_make_text(&name, "Name: ", TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    gui_make_text(&name, multisig_name, TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    *actname = make_show_single_value_activity("Wallet Name", multisig_name, show_help_btn);

    // Second row, type
    gui_view_node_t* splittype;
    gui_make_hsplit(&splittype, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* type;
    gui_make_text(&type, "Type: ", TFT_WHITE);
    gui_set_align(type, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(type, splittype);

    char typestr[16];
    const int ret = snprintf(typestr, sizeof(typestr), "%uof%u", threshold, num_signers);
    JADE_ASSERT(ret > 0 && ret < sizeof(typestr));

    gui_make_text(&type, typestr, TFT_WHITE);
    gui_set_align(type, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(type, splittype);

    *acttype = make_show_single_value_activity("Type", typestr, show_help_btn);

    // Show a warning if overwriting an existing registration or if signer details not available
    const char* warning_1 = NULL;
    const char* warning_2 = NULL;
    if (overwriting) {
        JADE_ASSERT(num_signer_details == num_signers);
        warning_1 = "WARNING";
        warning_2 = "Overwriting existing";
    } else if (num_signer_details < num_signers) {
        JADE_ASSERT(!initial_confirmation);
        warning_1 = "Complete signer";
        warning_2 = "Details unavailable";
    }

    // Buttons - Delete and Next
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MULTISIG_DISCARD_DELETE },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_MULTISIG_RETAIN_CONFIRM } };

    btn_data_t menubtns[]
        = { { .content = splitname, .ev_id = BTN_MULTISIG_NAME }, { .content = splittype, .ev_id = BTN_MULTISIG_TYPE },
              { .txt = warning_1, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
              { .txt = warning_2, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    const char* title = initial_confirmation ? "Register Multisig" : "Registered Wallet";
    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 4);

    // Set the intially selected item to 'Discard' when confirming new record
    // but to 'Retain' when viewing existing record.
    gui_set_activity_initial_selection(act, hdrbtns[initial_confirmation ? 0 : 1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(type, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

static bool show_final_multisig_summary_activity(const char* multisig_name, const size_t threshold,
    const size_t num_signers, const size_t num_signer_details, const bool initial_confirmation, const bool overwriting)
{
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(threshold <= num_signers);
    JADE_ASSERT(num_signer_details <= num_signers);
    JADE_ASSERT(!overwriting || initial_confirmation);

    gui_activity_t* act_name = NULL;
    gui_activity_t* act_type = NULL;
    gui_activity_t* act_summary = make_final_multisig_summary_activities(multisig_name, threshold, num_signers,
        num_signer_details, initial_confirmation, overwriting, &act_name, &act_type);
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
        ev_id = BTN_MULTISIG_RETAIN_CONFIRM;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_summary;
                break;

            case BTN_MULTISIG_NAME:
                act = act_name;
                break;

            case BTN_MULTISIG_TYPE:
                act = act_type;
                break;

            case BTN_MULTISIG_DISCARD_DELETE:
                return false;

            case BTN_MULTISIG_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}

bool show_multisig_activity(const char* multisig_name, const bool is_sorted, const size_t threshold,
    const size_t num_signers, const signer_t* signer_details, const size_t num_signer_details,
    const char* master_blinding_key_hex, const uint8_t* wallet_fingerprint, const size_t wallet_fingerprint_len,
    const bool initial_confirmation, const bool overwriting, const bool is_valid)
{
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(threshold > 0);
    JADE_ASSERT(num_signers >= threshold);
    JADE_ASSERT(signer_details || !num_signer_details);
    JADE_ASSERT(wallet_fingerprint);
    JADE_ASSERT(wallet_fingerprint_len == BIP32_KEY_FINGERPRINT_LEN);

    // Overwriting only applies to intial confirmations - which cannot be invalid
    JADE_ASSERT(!overwriting || initial_confirmation);
    JADE_ASSERT(!initial_confirmation || is_valid);

    // NOTE: because multisig potentially has a lot of signers and info to display
    // we deal with the signers one at a time, rather than creating them all up-front.
    gui_activity_t* act_clear = gui_make_activity();
    bool confirmed = false;
    uint8_t screen = 0; // 0 = initial summary, 1->n = signers, n+1 = final summary
    while (true) {
        JADE_ASSERT(screen <= num_signer_details + 1);
        if (screen == 0) {
            confirmed = show_view_multisig_activity(multisig_name, initial_confirmation, is_valid, is_sorted, threshold,
                num_signers, master_blinding_key_hex);
            if (confirmed && is_valid) {
                // Show more details
                ++screen;
            } else {
                // either details not valid or record has been rejected
                break;
            }
        } else if (screen > num_signer_details) {
            confirmed = show_final_multisig_summary_activity(
                multisig_name, threshold, num_signers, num_signer_details, initial_confirmation, overwriting);
            if (confirmed) {
                // User pressed 'confirm'
                break;
            } else {
                // User pressed 'back'
                --screen;
            }
        } else {
            JADE_ASSERT(signer_details);

            // Free all existing activities between signers
            gui_set_current_activity_ex(act_clear, true);

            const uint8_t signer_index = screen - 1;
            const signer_t* signer = signer_details + signer_index;
            const bool is_this_signer = !sodium_memcmp(signer->fingerprint, wallet_fingerprint, wallet_fingerprint_len);
            if (show_multisig_signer_activity(signer, signer_index + 1, num_signers, is_this_signer)) {
                // User pressed 'next'
                ++screen;
            } else {
                // User pressed 'back'
                --screen;
            }
        }
    }

    return confirmed;
}
