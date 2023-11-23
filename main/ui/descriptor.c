#include "../descriptor.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"
#include "../utils/event.h"
#include "../utils/util.h"

#include <sodium/utils.h>

bool show_signer_activity(const signer_t* signer, size_t signer_number, size_t num_signers, bool is_this_signer);

static gui_activity_t* make_view_descriptor_activities(const char* descriptor_name, const bool initial_confirmation,
    const bool is_valid, const descriptor_data_t* descriptor, gui_activity_t** actname, gui_activity_t** actscript1,
    gui_activity_t** actscript2, gui_activity_t** actscript3)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);
    JADE_INIT_OUT_PPTR(actname);
    JADE_INIT_OUT_PPTR(actscript1);
    JADE_INIT_OUT_PPTR(actscript2);
    JADE_INIT_OUT_PPTR(actscript3);

    // initial confirmations can't be invalid
    JADE_ASSERT(!initial_confirmation || is_valid);

    const bool show_help_btn = false;
    char display_str[96];

    // First row, name
    gui_view_node_t* splitname;
    gui_make_hsplit(&splitname, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* name;
    gui_make_text(&name, "Name: ", TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    gui_make_text(&name, descriptor_name, TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    *actname = make_show_single_value_activity("Wallet Name", descriptor_name, show_help_btn);

    // If not valid, no details, just message
    if (!is_valid) {
        // Create 'name' button and warning
        btn_data_t hdrbtns[]
            = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_DESCRIPTOR_RETAIN_CONFIRM },
                  { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_DESCRIPTOR_DISCARD_DELETE } };

        btn_data_t menubtns[] = { { .content = splitname, .ev_id = BTN_DESCRIPTOR_NAME },
            { .txt = "Not valid for", .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = "current wallet", .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

        gui_activity_t* const act = make_menu_activity("Registered Wallet", hdrbtns, 2, menubtns, 4);

        // NOTE: can only set scrolling *after* gui tree created
        gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
        return act;
    }

    // Second row, script
    gui_view_node_t* splitscript;
    gui_make_hsplit(&splitscript, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* script;
    gui_make_text(&script, "Script: ", TFT_WHITE);
    gui_set_align(script, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(script, splitscript);

    gui_make_text(&script, descriptor->script, TFT_WHITE);
    gui_set_align(script, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(script, splitscript);

    // NOTE: can be up to three script display screens
    if (descriptor->script_len > (2 * sizeof(descriptor->script) / 3)) {
        // Three screens to show script
        // Two screens to show script
        const size_t display_len = descriptor->script_len / 3;
        JADE_ASSERT(display_len + 2 <= sizeof(display_str));
        const char* message[] = { display_str };

        // First screen needs a 'next' button
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_DESCRIPTOR_SCRIPT_NEXT } };

        int ret = snprintf(display_str, sizeof(display_str), "\n%.*s", display_len, descriptor->script);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actscript1 = make_show_message_activity(message, 1, "Script (1/3)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actscript1, hdrbtns[1].btn);

        // Second screen similar to first
        ret = snprintf(display_str, sizeof(display_str), "\n%.*s", display_len, descriptor->script + display_len);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actscript2 = make_show_message_activity(message, 1, "Script (2/3)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actscript2, hdrbtns[1].btn);

        // Third message screen has a tick button
        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;

        ret = snprintf(display_str, sizeof(display_str), "\n%s", descriptor->script + (2 * display_len));
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actscript3 = make_show_message_activity(message, 1, "Script (3/3)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actscript3, hdrbtns[1].btn);
    } else if (descriptor->script_len > sizeof(descriptor->script) / 3) {
        // Two screens to show script
        const size_t display_len = descriptor->script_len / 2;
        JADE_ASSERT(display_len + 2 <= sizeof(display_str));
        const char* message[] = { display_str };

        // First screen needs a 'next' button
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_DESCRIPTOR_SCRIPT_NEXT } };

        int ret = snprintf(display_str, sizeof(display_str), "\n%.*s", display_len, descriptor->script);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actscript1 = make_show_message_activity(message, 1, "Script (1/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actscript1, hdrbtns[1].btn);

        // Second message screen has a tick button
        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;

        ret = snprintf(display_str, sizeof(display_str), "\n%s", descriptor->script + display_len);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
        *actscript2 = make_show_message_activity(message, 1, "Script (2/2)", hdrbtns, 2, NULL, 0);

        // Set the intially selected item to the 'Next' button
        gui_set_activity_initial_selection(*actscript2, hdrbtns[1].btn);

        *actscript3 = NULL;
    } else {
        // Just the one script screen
        *actscript1 = make_show_single_value_activity("Script", descriptor->script, show_help_btn);
        *actscript2 = NULL;
        *actscript3 = NULL;
    }

    // Buttons - Delete and Next
    btn_data_t hdrbtns[] = { { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_DESCRIPTOR_DISCARD_DELETE },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_DESCRIPTOR_RETAIN_CONFIRM } };

    btn_data_t menubtns[] = { { .content = splitname, .ev_id = BTN_DESCRIPTOR_NAME },
        { .content = splitscript, .ev_id = BTN_DESCRIPTOR_SCRIPT } };

    const char* title = initial_confirmation ? "Register Descriptor" : "Registered Wallet";
    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 2);

    // Set the intially selected item to the 'Next' button
    gui_set_activity_initial_selection(act, hdrbtns[1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(script, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

// multisig details screen for viewing or confirmation
// returns true if we are to store/retain this record, false if we are to discard/delete the record
bool show_view_descriptor_activity(const char* descriptor_name, const descriptor_data_t* descriptor,
    const bool initial_confirmation, const bool is_valid)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);

    gui_activity_t* act_name = NULL;
    gui_activity_t* act_script1 = NULL;
    gui_activity_t* act_script2 = NULL;
    gui_activity_t* act_script3 = NULL;
    gui_activity_t* act_summary = make_view_descriptor_activities(descriptor_name, initial_confirmation, is_valid,
        descriptor, &act_name, &act_script1, &act_script2, &act_script3);
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
        ev_id = BTN_DESCRIPTOR_RETAIN_CONFIRM;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = (act == act_script3) ? act_script2 : (act == act_script2) ? act_script1 : act_summary;
                break;

            case BTN_DESCRIPTOR_NAME:
                act = act_name;
                break;

            case BTN_DESCRIPTOR_SCRIPT:
                act = act_script1;
                break;

            case BTN_DESCRIPTOR_SCRIPT_NEXT:
                act = (act == act_script2 && act_script3) ? act_script3
                    : (act == act_script1)                ? act_script2
                                                          : act_summary;
                break;

            case BTN_DESCRIPTOR_DISCARD_DELETE:
                return false;

            case BTN_DESCRIPTOR_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}

static gui_activity_t* make_final_descriptor_summary_activities(
    const char* descriptor_name, const bool initial_confirmation, const bool overwriting, gui_activity_t** actname)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(!overwriting || initial_confirmation);
    JADE_INIT_OUT_PPTR(actname);

    const bool show_help_btn = false;

    // First row, name
    gui_view_node_t* splitname;
    gui_make_hsplit(&splitname, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* name;
    gui_make_text(&name, "Name: ", TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    gui_make_text(&name, descriptor_name, TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    *actname = make_show_single_value_activity("Wallet Name", descriptor_name, show_help_btn);

    // Show a warning if overwriting an existing registration
    const char* overwrite_warning_1 = overwriting ? "WARNING" : NULL;
    const char* overwrite_warning_2 = overwriting ? "Overwriting existing" : NULL;

    // Buttons - Delete and Next
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_DESCRIPTOR_DISCARD_DELETE },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_DESCRIPTOR_RETAIN_CONFIRM } };

    btn_data_t menubtns[] = { { .content = splitname, .ev_id = BTN_DESCRIPTOR_NAME },
        { .txt = overwrite_warning_1, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
        { .txt = overwrite_warning_2, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    const char* title = initial_confirmation ? "Register Descriptor" : "Registered Wallet";
    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 3);

    // Set the intially selected item to 'Discard' when confirming new record
    // but to 'Retain' when viewing existing record.
    gui_set_activity_initial_selection(act, hdrbtns[initial_confirmation ? 0 : 1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

static bool show_final_descriptor_summary_activity(
    const char* descriptor_name, const bool initial_confirmation, const bool overwriting)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(!overwriting || initial_confirmation);

    gui_activity_t* act_name = NULL;
    gui_activity_t* act_summary
        = make_final_descriptor_summary_activities(descriptor_name, initial_confirmation, overwriting, &act_name);
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
        ev_id = BTN_DESCRIPTOR_RETAIN_CONFIRM;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_summary;
                break;

            case BTN_DESCRIPTOR_NAME:
                act = act_name;
                break;

            case BTN_DESCRIPTOR_DISCARD_DELETE:
                return false;

            case BTN_DESCRIPTOR_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}

bool show_descriptor_activity(const char* descriptor_name, const descriptor_data_t* descriptor,
    const signer_t* signer_details, const size_t num_signer_details, const uint8_t* wallet_fingerprint,
    const size_t wallet_fingerprint_len, const bool initial_confirmation, const bool overwriting, const bool is_valid)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(signer_details);
    JADE_ASSERT(num_signer_details == descriptor->num_values);

    // Overwriting only applies to intial confirmations - which cannot be invalid
    JADE_ASSERT(!overwriting || initial_confirmation);
    JADE_ASSERT(!initial_confirmation || is_valid);

    // NOTE: because the descriptor potentially has a lot of signers/parameters and info to display
    // we deal with the data values one at a time, rather than creating them all up-front.
    gui_activity_t* act_clear = gui_make_activity();
    bool confirmed = false;
    uint8_t screen = 0; // 0 = initial summary, 1->n = signers, n+1 = final summary
    while (true) {
        JADE_ASSERT(screen <= descriptor->num_values + 1);
        if (screen == 0) {
            confirmed = show_view_descriptor_activity(descriptor_name, descriptor, initial_confirmation, is_valid);
            if (confirmed && is_valid) {
                // Show more details
                ++screen;
            } else {
                // either details not valid or record has been rejected
                break;
            }
        } else if (screen > descriptor->num_values) {
            confirmed = show_final_descriptor_summary_activity(descriptor_name, initial_confirmation, overwriting);
            if (confirmed) {
                // User pressed 'confirm'
                break;
            } else {
                // User pressed 'back'
                --screen;
            }
        } else {
            // Free all existing activities between signers/parameters
            gui_set_current_activity_ex(act_clear, true);

            const uint8_t signer_index = screen - 1;
            const signer_t* signer = signer_details + signer_index;
            const bool is_this_signer = !sodium_memcmp(signer->fingerprint, wallet_fingerprint, wallet_fingerprint_len);
            if (show_signer_activity(signer, signer_index + 1, num_signer_details, is_this_signer)) {
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
