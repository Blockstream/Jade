#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void await_qr_help_activity(const char* url);

// Make summary activity and all drilldown activities
static gui_activity_t* make_ota_versions_activities(const char* current_version, const char* new_version,
    const char* hashstr, const bool full_fw_hash, gui_activity_t** actcurrentver, gui_activity_t** actnewver,
    gui_activity_t** acthash)
{
    JADE_ASSERT(current_version);
    JADE_ASSERT(new_version);
    JADE_ASSERT(hashstr);
    JADE_INIT_OUT_PPTR(actcurrentver);
    JADE_INIT_OUT_PPTR(actnewver);
    JADE_INIT_OUT_PPTR(acthash);

    const char* hashtitle = full_fw_hash ? "Fw Hash:" : "File Hash:";
    const bool show_help_btn = true;

    // First row, current version
    gui_view_node_t* splitcurrent;
    gui_make_hsplit(&splitcurrent, GUI_SPLIT_RELATIVE, 2, 36, 64);

    gui_view_node_t* vercurrent;
    gui_make_text(&vercurrent, "Current:", TFT_WHITE);
    gui_set_align(vercurrent, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(vercurrent, splitcurrent);

    gui_make_text(&vercurrent, current_version, TFT_WHITE);
    gui_set_align(vercurrent, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(vercurrent, splitcurrent);

    *actcurrentver = make_show_single_value_activity("Current Version", current_version, show_help_btn);

    // Second row, new version
    gui_view_node_t* splitnew;
    gui_make_hsplit(&splitnew, GUI_SPLIT_RELATIVE, 2, 36, 64);

    gui_view_node_t* vernew;
    gui_make_text(&vernew, "New:", TFT_WHITE);
    gui_set_align(vernew, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(vernew, splitnew);

    gui_make_text(&vernew, new_version, TFT_WHITE);
    gui_set_align(vernew, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(vernew, splitnew);

    *actnewver = make_show_single_value_activity("New Version", new_version, show_help_btn);

    // Third row, hash
    gui_view_node_t* splithash;
    gui_make_hsplit(&splithash, GUI_SPLIT_RELATIVE, 2, 45, 55);

    gui_view_node_t* fwhash;
    gui_make_text(&fwhash, hashtitle, TFT_WHITE);
    gui_set_align(fwhash, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(fwhash, splithash);

    gui_make_text(&fwhash, hashstr, TFT_WHITE);
    gui_set_align(fwhash, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(fwhash, splithash);

    *acthash = make_show_single_value_activity(hashtitle, hashstr, show_help_btn);

    // Create buttons/menu
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_OTA_REJECT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_OTA_ACCEPT } };

    btn_data_t menubtns[] = { { .content = splitcurrent, .ev_id = BTN_OTA_VIEW_CURRENT_VERSION },
        { .content = splitnew, .ev_id = BTN_OTA_VIEW_NEW_VERSION },
        { .content = splithash, .ev_id = BTN_OTA_VIEW_FW_HASH } };

    gui_activity_t* const act = make_menu_activity("Firmware Upgrade", hdrbtns, 2, menubtns, 3);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(vercurrent, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(vernew, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(fwhash, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

// ota version details screen for user confirmation
bool show_ota_versions_activity(
    const char* current_version, const char* new_version, const char* hashhex, const bool full_fw_hash)
{
    JADE_ASSERT(current_version);
    JADE_ASSERT(new_version);
    JADE_ASSERT(hashhex);

    // Break up hash string into groups of 8 chars
    char hashstr[96];
    JADE_ASSERT(strlen(hashhex) == 64);
    const int ret = snprintf(hashstr, sizeof(hashstr), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s", 8, hashhex, 8,
        hashhex + 8, 8, hashhex + 16, 8, hashhex + 24, 8, hashhex + 32, 8, hashhex + 40, 8, hashhex + 48, 8,
        hashhex + 56);
    JADE_ASSERT(ret > 0 && ret < sizeof(hashstr));

    gui_activity_t* act_currentver = NULL;
    gui_activity_t* act_newver = NULL;
    gui_activity_t* act_hash = NULL;
    gui_activity_t* act_summary = make_ota_versions_activities(
        current_version, new_version, hashstr, full_fw_hash, &act_currentver, &act_newver, &act_hash);

    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_OTA_ACCEPT);
        switch (ev_id) {
        case BTN_BACK:
            act = act_summary;
            break;

        case BTN_OTA_VIEW_CURRENT_VERSION:
            act = act_currentver;
            break;

        case BTN_OTA_VIEW_NEW_VERSION:
            act = act_newver;
            break;

        case BTN_OTA_VIEW_FW_HASH:
            act = act_hash;
            break;

        case BTN_HELP:
            await_qr_help_activity("blkstrm.com/fwupgrade");
            break;

        case BTN_OTA_REJECT:
            return false;

        case BTN_OTA_ACCEPT:
            return true;
        }
    }
}
#endif // AMALGAMATED_BUILD
