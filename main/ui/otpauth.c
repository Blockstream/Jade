#ifndef AMALGAMATED_BUILD
#include <inttypes.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../otpauth.h"
#include "../ui.h"
#include "../utils/event.h"
#include "../utils/urldecode.h"

#include <time.h>

void await_qr_help_activity(const char* url);

// Make summary activity and all drilldown activities
static gui_activity_t* make_otp_details_activities(const otpauth_ctx_t* ctx, const bool initial_confirmation,
    const bool is_valid, const bool show_delete_btn, gui_activity_t** actname, gui_activity_t** actlabel,
    gui_activity_t** actissuer, gui_activity_t** acttype)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(ctx->name);
    JADE_INIT_OUT_PPTR(actname);
    JADE_INIT_OUT_PPTR(actlabel);
    JADE_INIT_OUT_PPTR(actissuer);
    JADE_INIT_OUT_PPTR(acttype);

    // initial confirmations can't be invalid, nor can they be deleted
    JADE_ASSERT(!initial_confirmation || is_valid);
    JADE_ASSERT(!initial_confirmation || !show_delete_btn);

    const char* const title = initial_confirmation ? "Confirm OTP" : "OTP Details";
    const bool show_help_btn = false;
    char display_str[128];

    // First row, name
    gui_view_node_t* splitname;
    gui_make_hsplit(&splitname, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* name;
    gui_make_text(&name, "Name: ", TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    gui_make_text(&name, ctx->name, TFT_WHITE);
    gui_set_align(name, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(name, splitname);

    *actname = make_show_single_value_activity("OTP Name", ctx->name, show_help_btn);

    // If not valid, no details, just message
    if (!is_valid) {
        // Create 'name' button and warning
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_OTP_RETAIN_CONFIRM },
            { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_OTP_DISCARD_DELETE } };

        btn_data_t menubtns[] = { { .content = splitname, .ev_id = BTN_OTA_VIEW_CURRENT_VERSION },
            { .txt = "Not valid for", .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = "current wallet", .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

        gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 4);

        // NOTE: can only set scrolling *after* gui tree created
        gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
        return act;
    }

    // Second row, label
    gui_view_node_t* splitlabel;
    gui_make_hsplit(&splitlabel, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* label;
    gui_make_text(&label, "Label: ", TFT_WHITE);
    gui_set_align(label, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(label, splitlabel);

    if (ctx->label && ctx->label_len) {
        // urldecode the label string - use font with no messed-with characters
        urldecode(ctx->label, ctx->label_len, display_str, sizeof(display_str));
    } else {
        const int ret = snprintf(display_str, sizeof(display_str), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
    }
    gui_make_text(&label, display_str, TFT_WHITE);
    gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(label, splitlabel);

    *actlabel = make_show_single_value_activity("Label", display_str, show_help_btn);

    // Third row, issuer
    gui_view_node_t* splitissuer;
    gui_make_hsplit(&splitissuer, GUI_SPLIT_RELATIVE, 2, 35, 65);

    gui_view_node_t* issuer;
    gui_make_text(&issuer, "Issuer: ", TFT_WHITE);
    gui_set_align(issuer, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(issuer, splitissuer);

    if (ctx->issuer && ctx->issuer_len) {
        // urldecode the issuer string - use font with no messed-with characters
        urldecode(ctx->issuer, ctx->issuer_len, display_str, sizeof(display_str));
    } else {
        const int ret = snprintf(display_str, sizeof(display_str), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));
    }
    gui_make_text(&issuer, display_str, TFT_WHITE);
    gui_set_align(issuer, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(issuer, splitissuer);

    *actissuer = make_show_single_value_activity("Issuer", display_str, show_help_btn);

    gui_view_node_t* splittype;
    gui_make_hsplit(&splittype, GUI_SPLIT_RELATIVE, 2, 35, 65);

    // Fourth row, type
    gui_view_node_t* type;
    gui_make_text(&type, "Type: ", TFT_WHITE);
    gui_set_align(type, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(type, splittype);

    const int ret
        = snprintf(display_str, sizeof(display_str), "%s / %s", ctx->otp_type == OTPTYPE_TOTP ? "TOTP" : "HOTP",
            ctx->md_type == MDTYPE_SHA512       ? "SHA512"
                : ctx->md_type == MDTYPE_SHA256 ? "SHA256"
                                                : "SHA1");
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    gui_make_text(&type, display_str, TFT_WHITE);
    gui_set_align(type, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(type, splittype);

    *acttype = make_show_single_value_activity("Type", display_str, show_help_btn);

    // Create buttons/menu for details view
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_OTP_RETAIN_CONFIRM },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_SETTINGS_OTP_HELP } };

    // For initial confirmation, the 'back' button is 'discard' rather than 'retain'
    // and the 'help' button is replaced by a 'confirm' button.
    if (initial_confirmation) {
        hdrbtns[0].ev_id = BTN_OTP_DISCARD_DELETE;

        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;
        hdrbtns[1].ev_id = BTN_OTP_RETAIN_CONFIRM;
    } else if (show_delete_btn) {
        hdrbtns[1].txt = "X";
        hdrbtns[1].font = GUI_TITLE_FONT;
        hdrbtns[1].ev_id = BTN_OTP_DISCARD_DELETE;
    }

    btn_data_t menubtns[]
        = { { .content = splitname, .ev_id = BTN_OTP_NAME }, { .content = splitlabel, .ev_id = BTN_OTP_LABEL },
              { .content = splitissuer, .ev_id = BTN_OTP_ISSUER }, { .content = splittype, .ev_id = BTN_OTP_TYPE } };

    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 4);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(name, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(label, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(issuer, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(type, true, TFT_BLACK, gui_get_highlight_color());

    return act;
}

// otp details screen for viewing or confirmation
// returns true if we are to store/retain this record, false if we are to discard/delete the record
bool show_otp_details_activity(
    const otpauth_ctx_t* ctx, const bool initial_confirmation, const bool is_valid, const bool show_delete_btn)
{
    JADE_ASSERT(ctx);

    gui_activity_t* act_name = NULL;
    gui_activity_t* act_label = NULL;
    gui_activity_t* act_issuer = NULL;
    gui_activity_t* act_type = NULL;
    gui_activity_t* act_summary = make_otp_details_activities(
        ctx, initial_confirmation, is_valid, show_delete_btn, &act_name, &act_label, &act_issuer, &act_type);

    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_OTP_RETAIN_CONFIRM);
        if (ev_id != BTN_EVENT_TIMEOUT) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_summary;
                break;

            case BTN_OTP_NAME:
                act = act_name;
                break;

            case BTN_OTP_LABEL:
                act = act_label;
                break;

            case BTN_OTP_ISSUER:
                act = act_issuer;
                break;

            case BTN_OTP_TYPE:
                act = act_type;
                break;

            case BTN_SETTINGS_OTP_HELP:
                await_qr_help_activity("blkstrm.com/otp");
                break;

            case BTN_OTP_DISCARD_DELETE:
                return false;

            case BTN_OTP_RETAIN_CONFIRM:
                return true;
            }
        }
    }
}

gui_activity_t* make_show_hotp_code_activity(const char* name, const char* codestr, const bool confirm_only)
{
    JADE_ASSERT(name);
    JADE_ASSERT(codestr);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_OTP_RETAIN_CONFIRM },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // For code confirmation, the 'back' button is 'reject' rather than 'confirm'
    // and we add a 'confirm' button also.
    if (confirm_only) {
        hdrbtns[0].ev_id = BTN_OTP_DISCARD_DELETE;

        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;
        hdrbtns[1].ev_id = BTN_OTP_RETAIN_CONFIRM;
    }

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, name, hdrbtns, 2, NULL);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(vsplit, parent);

    // Display the OTP code large/central
    gui_make_text_font(&node, codestr, TFT_WHITE, DEJAVU24_FONT);
    gui_set_parent(node, vsplit);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // If not in 'confirm only' mode, add 'details' and 'delete' footer buttons
    if (!confirm_only) {
        btn_data_t ftrbtns[] = {
            { .txt = "Details", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_DETAILS, .borders = GUI_BORDER_TOPRIGHT },
            { .txt = "Delete",
                .font = GUI_DEFAULT_FONT,
                .ev_id = BTN_OTP_DISCARD_DELETE,
                .borders = GUI_BORDER_TOPLEFT }
        };
        add_buttons(vsplit, UI_ROW, ftrbtns, 2);
    }

    return act;
}

gui_activity_t* make_show_totp_code_activity(const char* name, const char* timestr, const char* codestr,
    const bool confirm_only, progress_bar_t* progress_bar, gui_view_node_t** txt_ts, gui_view_node_t** txt_code)
{
    JADE_ASSERT(name);
    JADE_ASSERT(timestr);
    JADE_ASSERT(codestr);
    JADE_ASSERT(progress_bar);
    JADE_INIT_OUT_PPTR(txt_ts);
    JADE_INIT_OUT_PPTR(txt_code);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_OTP_RETAIN_CONFIRM },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // For code confirmation, the 'back' button is 'reject' rather than 'confirm'
    // and we add a 'confirm' button also.
    if (confirm_only) {
        hdrbtns[0].ev_id = BTN_OTP_DISCARD_DELETE;

        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;
        hdrbtns[1].ev_id = BTN_OTP_RETAIN_CONFIRM;
    }

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, name, hdrbtns, 2, NULL);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    if (confirm_only) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 24, 28, 38, 10);
    } else {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 18, 20, 32, 30);
    }
    gui_set_parent(vsplit, parent);

    // Display timestamp string
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 15, 85);
    gui_set_parent(hsplit, vsplit);

    gui_make_text_font(&node, "UTC", TFT_WHITE, DEFAULT_FONT);
    gui_set_parent(node, hsplit);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, hsplit);

    gui_make_text_font(txt_ts, timestr, TFT_WHITE, DEFAULT_FONT);
    gui_set_parent(*txt_ts, node);
    gui_set_align(*txt_ts, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Display 'progress' bar (time remaining)
    make_progress_bar(vsplit, progress_bar);

    // Display the OTP code large/central
    gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, vsplit);

    gui_make_text_font(txt_code, codestr, TFT_WHITE, DEJAVU24_FONT);
    gui_set_parent(*txt_code, node);
    gui_set_align(*txt_code, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // If not in 'confirm only' mode, add 'details' and 'delete' footer buttons
    if (!confirm_only) {
        btn_data_t ftrbtns[] = {
            { .txt = "Details", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_DETAILS, .borders = GUI_BORDER_TOPRIGHT },
            { .txt = "Delete",
                .font = GUI_DEFAULT_FONT,
                .ev_id = BTN_OTP_DISCARD_DELETE,
                .borders = GUI_BORDER_TOPLEFT }
        };
        add_buttons(vsplit, UI_ROW, ftrbtns, 2);
    }

    return act;
}
#endif // AMALGAMATED_BUILD
