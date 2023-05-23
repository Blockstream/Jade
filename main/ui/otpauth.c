#include <inttypes.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../otpauth.h"
#include "../ui.h"
#include "../utils/event.h"
#include "../utils/urldecode.h"

#include <time.h>

// Internal helper
// NOTE: 'parent' should be a vsplit of sufficient capacity - 4 rows will be added
static bool populate_otp_screen(gui_view_node_t* parent, const otpauth_ctx_t* ctx, const bool valid)
{
    JADE_ASSERT(parent && parent->kind == VSPLIT);
    JADE_ASSERT(ctx);
    JADE_ASSERT(ctx->name);

    char display_str[128];

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_set_parent(hsplit, parent);

        gui_view_node_t* txtlabel;
        gui_make_text(&txtlabel, "Name", TFT_WHITE);
        gui_set_parent(txtlabel, hsplit);
        gui_set_align(txtlabel, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* txtvalue;
        gui_make_text(&txtvalue, ctx->name, TFT_WHITE);
        gui_set_parent(txtvalue, hsplit);
        gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    }

    if (!valid) {
        gui_view_node_t* row2;
        gui_make_fill(&row2, TFT_BLACK);
        gui_set_parent(row2, parent);

        gui_view_node_t* text3;
        gui_make_text(&text3, "Not valid for this wallet", TFT_RED);
        gui_set_parent(text3, parent);
        gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* row4;
        gui_make_fill(&row4, TFT_BLACK);
        gui_set_parent(row4, parent);

        return false;
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_set_parent(hsplit, parent);

        gui_view_node_t* txtlabel;
        gui_make_text(&txtlabel, "Label", TFT_WHITE);
        gui_set_parent(txtlabel, hsplit);
        gui_set_align(txtlabel, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* txtvalue;
        if (ctx->label && ctx->label_len) {
            // urldecode the label string - use font with no messed-with characters
            urldecode(ctx->label, ctx->label_len, display_str, sizeof(display_str));
            gui_make_text_font(&txtvalue, display_str, TFT_WHITE, UBUNTU16_FONT);
            gui_set_parent(txtvalue, hsplit);
            gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
            gui_set_text_scroll(txtvalue, TFT_BLACK);
        } else {
            gui_make_text(&txtvalue, "<None>", TFT_WHITE);
            gui_set_parent(txtvalue, hsplit);
            gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        }
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 45, 55);
        gui_set_parent(hsplit, parent);

        gui_view_node_t* txtlabel;
        gui_make_text(&txtlabel, "Issuer", TFT_WHITE);
        gui_set_parent(txtlabel, hsplit);
        gui_set_align(txtlabel, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* txtvalue;
        if (ctx->issuer && ctx->issuer_len) {
            // urldecode the issuer string - use font with no messed-with characters
            urldecode(ctx->issuer, ctx->issuer_len, display_str, sizeof(display_str));
            gui_make_text_font(&txtvalue, display_str, TFT_WHITE, UBUNTU16_FONT);
            gui_set_parent(txtvalue, hsplit);
            gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
            gui_set_text_scroll(txtvalue, TFT_BLACK);
        } else {
            gui_make_text(&txtvalue, "<None>", TFT_WHITE);
            gui_set_parent(txtvalue, hsplit);
            gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        }
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_set_parent(hsplit, parent);

        gui_view_node_t* txtlabel;
        gui_make_text(&txtlabel, "Type", TFT_WHITE);
        gui_set_parent(txtlabel, hsplit);
        gui_set_align(txtlabel, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        const int ret
            = snprintf(display_str, sizeof(display_str), "%s / %s", ctx->otp_type == OTPTYPE_TOTP ? "TOTP" : "HOTP",
                ctx->md_type == MDTYPE_SHA512       ? "SHA512"
                    : ctx->md_type == MDTYPE_SHA256 ? "SHA256"
                                                    : "SHA1");
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

        gui_view_node_t* txtvalue;
        gui_make_text(&txtvalue, display_str, TFT_WHITE);
        gui_set_parent(txtvalue, hsplit);
        gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    }

    return true;
}

void make_confirm_otp_activity(gui_activity_t** activity_ptr, const otpauth_ctx_t* ctx)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(otp_is_valid(ctx));

    gui_make_activity(activity_ptr, true, "Confirm OTP");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Populate otp data - 4 rows
    const bool valid = populate_otp_screen(vsplit, ctx, true);
    JADE_ASSERT(valid);

    // Buttons - Cancel/Confirm
    btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_EXIT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_OTP_CONFIRM } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}

void make_view_otp_activity(
    gui_activity_t** activity_ptr, const size_t index, const size_t total, const bool valid, const otpauth_ctx_t* ctx)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(ctx);

    char header[16];
    const int ret = snprintf(header, sizeof(header), "OTP %d/%d", index, total);
    JADE_ASSERT(ret > 0 && ret < sizeof(header));
    gui_make_activity(activity_ptr, true, header);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 4, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Populate otp data
    populate_otp_screen(vsplit, ctx, valid);

    // Buttons - Delete, Generate (if record valid), Next[Exit]
    btn_data_t btns[] = { { .txt = "Delete", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_DELETE },
        { .txt = "Generate", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_GENERATE },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_OTP_NEXT } };

    // Remove 'Generate' if not valid
    if (!valid) {
        btns[1].txt = NULL;
        btns[1].ev_id = GUI_BUTTON_EVENT_NONE;
    }

    // Change 'Next' to 'Exit' for last entry
    if (index >= total) {
        btns[2].txt = "Exit";
        btns[2].font = GUI_DEFAULT_FONT;
        btns[2].ev_id = BTN_OTP_EXIT;
    }

    add_buttons(vsplit, UI_ROW, btns, 3);

    // Set the intially selected item to the 'Next' button (ie. btn[2])
    gui_set_activity_initial_selection(*activity_ptr, btns[2].btn);
}

void make_show_hotp_code_activity(
    gui_activity_t** activity_ptr, const char* name, const char* codestr, const bool cancel_button)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(name);
    JADE_ASSERT(codestr);

    gui_make_activity(activity_ptr, true, name);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 4, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Display the OTP code large/central
    gui_view_node_t* txtvalue;
    gui_make_text_font(&txtvalue, codestr, TFT_WHITE, DEJAVU24_FONT);
    gui_set_parent(txtvalue, vsplit);
    gui_set_align(txtvalue, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    if (cancel_button) {
        // Two buttons - Cancel/Confirm
        btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_EXIT },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_OTP_CONFIRM } };
        add_buttons(vsplit, UI_ROW, btns, 2);
    } else {
        // Single 'ok' button
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_OTP_CONFIRM, NULL);
        gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 4, 50);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* text;
        gui_make_text_font(&text, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
        gui_set_parent(text, btn);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }
}

void make_show_totp_code_activity(gui_activity_t** activity_ptr, const char* name, const char* timestr,
    const char* codestr, const bool cancel_button, progress_bar_t* progress_bar, gui_view_node_t** txt_ts,
    gui_view_node_t** txt_code)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(name);
    JADE_ASSERT(timestr);
    JADE_ASSERT(codestr);
    JADE_ASSERT(progress_bar);
    JADE_INIT_OUT_PPTR(txt_ts);
    JADE_INIT_OUT_PPTR(txt_code);

    gui_make_activity(activity_ptr, true, name);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 17, 18, 35, 30);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 4, 2, 2);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // Display timestamp string
    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 15, 85);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* txtlabel;
        gui_make_text(&txtlabel, "UTC", TFT_WHITE);
        gui_set_parent(txtlabel, hsplit);
        gui_set_align(txtlabel, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text_bg;
        gui_make_fill(&text_bg, TFT_BLACK);
        gui_set_parent(text_bg, hsplit);

        gui_view_node_t* txtvalue;
        gui_make_text(&txtvalue, timestr, TFT_WHITE);
        gui_set_parent(txtvalue, text_bg);
        gui_set_align(txtvalue, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        *txt_ts = txtvalue;
    }

    // Display 'progress' bar (time remaining)
    make_progress_bar(vsplit, progress_bar);

    // Display the OTP code large/central
    {
        gui_view_node_t* text_bg;
        gui_make_fill(&text_bg, TFT_BLACK);
        gui_set_parent(text_bg, vsplit);

        gui_view_node_t* txtvalue;
        gui_make_text_font(&txtvalue, codestr, TFT_WHITE, DEJAVU24_FONT);
        gui_set_parent(txtvalue, text_bg);
        gui_set_align(txtvalue, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        *txt_code = txtvalue;
    }

    if (cancel_button) {
        // Two buttons - Cancel/Confirm
        btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_OTP_EXIT },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_OTP_CONFIRM } };
        add_buttons(vsplit, UI_ROW, btns, 2);
    } else {
        // Single 'ok' button
        btn_data_t btns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // spacer
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_OTP_CONFIRM },
            { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } }; // spacer
        add_buttons(vsplit, UI_ROW, btns, 3);
    }
}
