#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

static void make_qrcode(gui_view_node_t* parent, Icon* icons, const size_t num_icons, const size_t frames_per_qr_icon)
{
    // qrcodes are a background fill node with the icon node on top
    gui_view_node_t* fill;
    gui_make_fill(&fill, TFT_BLACK, FILL_QR, parent);

    gui_view_node_t* icon;
    gui_make_icon(&icon, icons, TFT_BLACK, &TFT_WHITE);
    gui_set_align(icon, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(icon, fill);
    gui_set_icon_animation(icon, icons, num_icons, frames_per_qr_icon);
    gui_set_icon_to_qr(icon);
}

static gui_view_node_t* make_back_brightness_row(gui_view_node_t* parent, uint32_t back_ev_id)
{
    // Create a row with left back arrow and right brightness button
    gui_view_node_t* headersplit;
    gui_make_hsplit(&headersplit, GUI_SPLIT_RELATIVE, 3, 27, 46, 27); // 27 x 56% (hsplit) == 15
    gui_set_parent(headersplit, parent);

    // back button, space, brightness button
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = back_ev_id, .borders = GUI_BORDER_ALL },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
              { .txt = "P", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_BRIGHTNESS, .borders = GUI_BORDER_ALL } };
    // Add individually to avoid creating a new equal 3-way split
    for (size_t i = 0; i < sizeof(hdrbtns) / sizeof(hdrbtns[0]); ++i) {
        add_button(headersplit, hdrbtns + i);
    }
    // Return the back button that add_button() created for the caller
    return hdrbtns[0].btn;
}

gui_activity_t* make_show_xpub_qr_activity(
    const char* label, const char* pathstr, Icon* icons, const size_t num_icons, const size_t frames_per_qr_icon)
{
    JADE_ASSERT(label);
    JADE_ASSERT(pathstr);
    JADE_ASSERT(icons);
    JADE_ASSERT(num_icons);

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* node;

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 44, 56);
    gui_set_parent(hsplit, act->root_node);

    // LHS
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 20, 30, 25, 25);
    gui_set_parent(vsplit, hsplit);

    // back button, space, brightness button
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_XPUB_EXIT, .borders = GUI_BORDER_ALL },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
              { .txt = "P", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_BRIGHTNESS, .borders = GUI_BORDER_ALL } };
    add_buttons(vsplit, UI_ROW, hdrbtns, 3); // 44 (hsplit) / 3 == 14 - almost 15 so ok

    // second row, type label
    gui_make_text(&node, label, TFT_WHITE);
    gui_set_parent(node, vsplit);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // third row, path
    gui_make_text_font(&node, pathstr, TFT_WHITE, DEFAULT_FONT); // fits path
    gui_set_parent(node, vsplit);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // button
    btn_data_t ftrbtn
        = { .txt = "Options", .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS, .borders = GUI_BORDER_TOP };
    add_buttons(vsplit, UI_COLUMN, &ftrbtn, 1);

    // RHS - QR icons
    make_qrcode(hsplit, icons, num_icons, frames_per_qr_icon);

    return act;
}

gui_activity_t* make_xpub_qr_options_activity(
    gui_view_node_t** script_textbox, gui_view_node_t** wallet_textbox, gui_view_node_t** account_textbox)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_XPUB_OPTIONS_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_XPUB_OPTIONS_HELP } };

    // menu buttons with bespoke content
    gui_make_text(script_textbox, "Script", TFT_WHITE);
    gui_set_align(*script_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_text(wallet_textbox, "Wallet", TFT_WHITE);
    gui_set_align(*wallet_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_text(account_textbox, "Account Index", TFT_WHITE);
    gui_set_align(*account_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // TODO maybe, add UR-type, hdkey or crypto-account ?
    btn_data_t menubtns[]
        = { { .content = *script_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS_SCRIPTTYPE },
              { .content = *wallet_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS_WALLETTYPE },
              { .content = *account_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS_ACCOUNT } };

    return make_menu_activity("Xpub Settings", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_search_verify_address_activity(
    const char* root_label, gui_view_node_t** label_text, progress_bar_t* progress_bar, gui_view_node_t** index_text)
{
    JADE_ASSERT(label_text);
    JADE_ASSERT(progress_bar);
    JADE_ASSERT(index_text);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SCAN_ADDRESS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, "Verify Address", hdrbtns, 2, NULL);
    gui_view_node_t* hsplit;
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, parent);

    // Progress bar
    make_progress_bar(vsplit, progress_bar);

    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(hsplit, vsplit);

    gui_make_text(&node, "Checking Index:", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(node, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_parent(node, hsplit);

    gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, hsplit);

    gui_make_text(index_text, "", TFT_WHITE);
    gui_set_align(*index_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*index_text, node);

    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 24, 76);
    gui_set_parent(hsplit, vsplit);

    gui_make_text(&node, "Root:", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(node, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_parent(node, hsplit);

    gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, hsplit);

    gui_make_text(label_text, root_label, TFT_WHITE);
    gui_set_align(*label_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*label_text, node);

    // buttons
    btn_data_t ftrbtns[] = { { .txt = "Skip",
                                 .font = GUI_DEFAULT_FONT,
                                 .ev_id = BTN_SCAN_ADDRESS_SKIP_ADDRESSES,
                                 .borders = GUI_BORDER_TOPRIGHT },
        { .txt = "Edit Root",
            .font = GUI_DEFAULT_FONT,
            .ev_id = BTN_SCAN_ADDRESS_OPTIONS,
            .borders = GUI_BORDER_TOPLEFT } };
    add_buttons(vsplit, UI_ROW, ftrbtns, 2);

    // Select 'Edit Root' button by default
    gui_set_activity_initial_selection(ftrbtns[1].btn);

    return act;
}

gui_activity_t* make_search_address_options_activity(
    const bool show_account, gui_view_node_t** account_textbox, gui_view_node_t** change_textbox)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SCAN_ADDRESS_OPTIONS_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // menu buttons with bespoke content
    if (show_account) {
        gui_make_text(account_textbox, "Account Index", TFT_WHITE);
        gui_set_align(*account_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        gui_make_text(change_textbox, "Change", TFT_WHITE);
        gui_set_align(*change_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        btn_data_t menubtns[]
            = { { .content = *account_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_SCAN_ADDRESS_OPTIONS_ACCOUNT },
                  { .content = *change_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_SCAN_ADDRESS_OPTIONS_CHANGE } };

        return make_menu_activity("Search Root", hdrbtns, 2, menubtns, 2);
    } else {
        gui_make_text(change_textbox, "Change", TFT_WHITE);
        gui_set_align(*change_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        btn_data_t menubtn
            = { .content = *change_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_SCAN_ADDRESS_OPTIONS_CHANGE };

        return make_menu_activity("Search Root", hdrbtns, 2, &menubtn, 1);
    }
}

gui_activity_t* make_qr_options_activity(gui_view_node_t** density_textbox, gui_view_node_t** framerate_textbox)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_OPTIONS_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_QR_OPTIONS_HELP } };

    // menu buttons with bespoke content
    gui_make_text(density_textbox, "QR Density", TFT_WHITE);
    gui_set_align(*density_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_text(framerate_textbox, "Frame Rate", TFT_WHITE);
    gui_set_align(*framerate_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    btn_data_t menubtns[]
        = { { .content = *density_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS_DENSITY },
              { .content = *framerate_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS_FRAMERATE } };

    return make_menu_activity("QR Settings", hdrbtns, 2, menubtns, 2);
}

// NOTE: 'icons' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_show_qr_activity(const char* message[], const size_t message_size, Icon* icons,
    const size_t num_icons, const size_t frames_per_qr_icon, const bool show_options_button, const bool show_help_btn)
{
    JADE_ASSERT(message);
    JADE_ASSERT(message_size < 4);
    JADE_ASSERT(icons);
    JADE_ASSERT(num_icons);
    JADE_ASSERT(frames_per_qr_icon || num_icons == 1);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 44, 56);
    gui_set_parent(hsplit, act->root_node);
    gui_view_node_t* node;

    // LHS
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 56, 24);
        gui_set_parent(vsplit, hsplit);

        // tick button
        btn_data_t hdrbtns[]
            = { { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_QR_DISPLAY_EXIT, .borders = GUI_BORDER_ALL },
                  { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
                  { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_QR_DISPLAY_HELP, .borders = GUI_BORDER_ALL } };

        if (!show_help_btn) {
            // Remove help button if not needed
            hdrbtns[2].txt = NULL;
            hdrbtns[2].font = GUI_DEFAULT_FONT;
            hdrbtns[2].ev_id = GUI_BUTTON_EVENT_NONE;
            hdrbtns[2].borders = 0; // None
        }

        add_buttons(vsplit, UI_ROW, hdrbtns, 3); // 44 (hsplit) / 3 == 14 - almost 15 so ok

        // text label
        gui_view_node_t* text_parent = vsplit;
        if (message_size > 1) {
            text_parent = make_even_split(UI_COLUMN, message_size);
            const size_t tbpad = ((3 - message_size) * 12) + 8;
            gui_set_padding(text_parent, GUI_MARGIN_TWO_VALUES, tbpad, 2);
            gui_set_parent(text_parent, vsplit);
        }
        for (size_t i = 0; i < message_size; ++i) {
            gui_make_text(&node, message[i], TFT_WHITE);
            gui_set_parent(node, text_parent);
            gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }

        // Buttons, optionally options
        if (show_options_button) {
            btn_data_t ftrbtn
                = { .txt = "Options", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS, .borders = GUI_BORDER_TOP };
            add_buttons(vsplit, UI_ROW, &ftrbtn, 1);
        }
    }

    // RHS - QR icons
    make_qrcode(hsplit, icons, num_icons, frames_per_qr_icon);

    return act;
}

// NOTE: 'qr_icon' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_show_qr_help_activity(const char* url, Icon* qr_icon)
{
    JADE_ASSERT(url);
    JADE_ASSERT(qr_icon);

#if CONFIG_DISPLAY_WIDTH >= 480 && CONFIG_DISPLAY_HEIGHT >= 220
    const size_t lpad = 12;
    const size_t vpad = 3;
#elif CONFIG_DISPLAY_WIDTH >= 320 && CONFIG_DISPLAY_HEIGHT >= 170
    const size_t lpad = 12;
    const size_t vpad = 10;
#else
    const size_t lpad = 4;
    const size_t vpad = 12;
#endif

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 56, 44);
    gui_set_parent(hsplit, act->root_node);
    gui_view_node_t* node;

    // LHS
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 25, 55);
        gui_set_parent(vsplit, hsplit);

        // first row, header: back button, space, brightness button
        make_back_brightness_row(vsplit, BTN_QR_HELP_EXIT);

        // second row, message
        gui_make_text(&node, "Learn more:", TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, lpad);
        gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

        // third row, url
        gui_make_text(&node, url, TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, lpad);
        gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    }

    // RHS - QR icon
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, vpad, 100 - (2 * vpad), vpad);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* fill;
        gui_make_fill(&fill, TFT_BLACK, FILL_PLAIN, vsplit);

        // QR icon
        make_qrcode(vsplit, qr_icon, 1, 0); // takes ownership of icon

        gui_make_fill(&fill, TFT_BLACK, FILL_PLAIN, vsplit);
    }

    return act;
}

// NOTE: 'qr_icon' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_qr_back_continue_activity(
    const char* message[], const size_t message_size, const char* url, Icon* qr_icon, const bool default_selection)
{
    JADE_ASSERT(message);
    JADE_ASSERT(message_size == 3);
    JADE_ASSERT(qr_icon);

#if CONFIG_DISPLAY_WIDTH >= 480 && CONFIG_DISPLAY_HEIGHT >= 220
    const size_t vpad = 3;
#elif CONFIG_DISPLAY_WIDTH >= 320 && CONFIG_DISPLAY_HEIGHT >= 170
    const size_t vpad = 10;
#else
    const size_t vpad = 12;
#endif

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 56, 44);
    gui_set_parent(hsplit, act->root_node);
    gui_view_node_t* node;

    // LHS
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 6, 20, 18, 16, 21, 25);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* back_btn = make_back_brightness_row(vsplit, BTN_NO);

        // second/third/fourth row, message
        gui_make_text(&node, message[0], TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_BOTTOM);
        gui_make_text(&node, message[1], TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_make_text(&node, message[2], TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

        // button, continue
        btn_data_t ftrbtn
            = { .txt = "Continue", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOP };
        add_buttons(vsplit, UI_ROW, &ftrbtn, 1);

        // Select default selected button
        gui_set_activity_initial_selection(default_selection ? ftrbtn.btn : back_btn);
    }

    // RHS - QR icon
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, vpad, 100 - (2 * vpad), vpad);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* fill;
        gui_make_fill(&fill, TFT_BLACK, FILL_PLAIN, vsplit);

        // QR icon background
        make_qrcode(vsplit, qr_icon, 1, 0); // takes ownership of icon

        gui_make_fill(&fill, TFT_BLACK, FILL_PLAIN, vsplit);
    }

    return act;
}
#endif // AMALGAMATED_BUILD
