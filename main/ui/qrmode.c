#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

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

    // back button
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_XPUB_EXIT, .borders = GUI_BORDER_ALL },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
              { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_XPUB_HELP, .borders = GUI_BORDER_ALL } };
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
    gui_view_node_t* fill;
    gui_make_fill(&fill, GUI_BLOCKSTREAM_QR_PALE);
    gui_set_parent(fill, hsplit);

    gui_make_icon(&node, icons, TFT_BLACK, &GUI_BLOCKSTREAM_QR_PALE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, fill);
    gui_set_icon_animation(node, icons, num_icons, frames_per_qr_icon);

    return act;
}

gui_activity_t* make_xpub_qr_options_activity(
    gui_view_node_t** script_textbox, gui_view_node_t** wallet_textbox, gui_view_node_t** density_textbox)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_XPUB_OPTIONS_EXIT },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_XPUB_OPTIONS_HELP } };

    // menu buttons with bespoke content
    gui_make_text(script_textbox, "Script", TFT_WHITE);
    gui_set_align(*script_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_text(wallet_textbox, "Wallet", TFT_WHITE);
    gui_set_align(*wallet_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_make_text(density_textbox, "QR Density", TFT_WHITE);
    gui_set_align(*density_textbox, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // TODO maybe, add UR-type, hdkey or crypto-account ?
    btn_data_t menubtns[]
        = { { .content = *script_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS_SCRIPTTYPE },
              { .content = *wallet_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS_WALLETTYPE },
              { .content = *density_textbox, .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS_DENSITY } };

    return make_menu_activity("Xpub Settings", hdrbtns, 2, menubtns, 3);
}

gui_activity_t* make_search_verify_address_activity(
    const char* root_label, progress_bar_t* progress_bar, gui_view_node_t** index_text)
{
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

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);

    gui_make_text(index_text, "", TFT_WHITE);
    gui_set_align(*index_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*index_text, node);

    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 24, 76);
    gui_set_parent(hsplit, vsplit);

    gui_make_text(&node, "Root:", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(node, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_parent(node, hsplit);

    gui_make_text(&node, root_label, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // buttons
    btn_data_t ftrbtn = {
        .txt = "Skip", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SCAN_ADDRESS_SKIP_ADDRESSES, .borders = GUI_BORDER_TOP
    };
    add_buttons(vsplit, UI_ROW, &ftrbtn, 1);

    // Select 'Skip' button by default
    gui_set_activity_initial_selection(act, ftrbtn.btn);

    return act;
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
gui_activity_t* make_show_qr_activity(const char* label, Icon* icons, const size_t num_icons,
    const size_t frames_per_qr_icon, const bool show_options_button, const bool show_help_btn)
{
    JADE_ASSERT(label);
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
        }

        add_buttons(vsplit, UI_ROW, hdrbtns, 3); // 44 (hsplit) / 3 == 14 - almost 15 so ok

        // second row, label
        gui_make_text(&node, label, TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, 4);
        gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

        // Buttons, optionally options
        if (show_options_button) {
            btn_data_t ftrbtn
                = { .txt = "Options", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS, .borders = GUI_BORDER_TOP };
            add_buttons(vsplit, UI_ROW, &ftrbtn, 1);
        }
    }

    // RHS - QR icons
    {
        gui_view_node_t* fill;
        gui_make_fill(&fill, GUI_BLOCKSTREAM_QR_PALE);
        gui_set_parent(fill, hsplit);

        gui_make_icon(&node, icons, TFT_BLACK, &GUI_BLOCKSTREAM_QR_PALE);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, fill);
        gui_set_icon_animation(node, icons, num_icons, frames_per_qr_icon);
    }

    return act;
}

// NOTE: 'qr_icon' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_show_qr_help_activity(const char* url, Icon* qr_icon)
{
    JADE_ASSERT(url);
    JADE_ASSERT(qr_icon);
    JADE_ASSERT(qr_icon->width <= 100);
    JADE_ASSERT(qr_icon->height <= 100);

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

        gui_view_node_t* headersplit;
        gui_make_hsplit(&headersplit, GUI_SPLIT_RELATIVE, 2, 27, 73); // 27 x 56 (hsplit) == 15
        gui_set_parent(headersplit, vsplit);

        // first row, header, back button
        btn_data_t hdrbtn
            = { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_HELP_EXIT, .borders = GUI_BORDER_ALL };
        add_buttons(headersplit, UI_ROW, &hdrbtn, 1);

        // second row, message
        gui_make_text(&node, "Learn more:", TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, 4);
        gui_set_align(node, GUI_ALIGN_TOP, GUI_ALIGN_LEFT);

        // third row, url
        gui_make_text(&node, url, TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, 4);
        gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    }

    // RHS - QR icon
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 12, 76, 12);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* fill;
        gui_make_fill(&fill, TFT_BLACK);
        gui_set_parent(fill, vsplit);

        // QR icon background
        gui_make_fill(&fill, GUI_BLOCKSTREAM_QR_PALE);
        gui_set_parent(fill, vsplit);

        gui_make_icon(&node, qr_icon, TFT_BLACK, &GUI_BLOCKSTREAM_QR_PALE);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, fill);
        gui_set_icon_animation(node, qr_icon, 1, 0); // takes ownership of icon

        gui_make_fill(&fill, TFT_BLACK);
        gui_set_parent(fill, vsplit);
    }

    return act;
}

// NOTE: 'qr_icon' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_qr_back_continue_activity(
    const char* label, const char* url, Icon* qr_icon, const bool default_selection)
{
    JADE_ASSERT(label);
    JADE_ASSERT(qr_icon);
    JADE_ASSERT(qr_icon->width <= 100);
    JADE_ASSERT(qr_icon->height <= 100);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 56, 44);
    gui_set_parent(hsplit, act->root_node);
    gui_view_node_t* node;

    // LHS
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 20, 55, 25);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* headersplit;
        gui_make_hsplit(&headersplit, GUI_SPLIT_RELATIVE, 2, 27, 73); // 27 x 56 (hsplit) == 15
        gui_set_parent(headersplit, vsplit);

        btn_data_t hdrbtn = { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_NO, .borders = GUI_BORDER_ALL };
        add_buttons(headersplit, UI_ROW, &hdrbtn, 1);

        // second row, message
        gui_make_text(&node, label, TFT_WHITE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 12, 0, 2, 4);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_LEFT);

        // button, continue
        btn_data_t ftrbtn
            = { .txt = "Continue", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOP };
        add_buttons(vsplit, UI_ROW, &ftrbtn, 1);

        // Select default selected button
        gui_set_activity_initial_selection(act, default_selection ? ftrbtn.btn : hdrbtn.btn);
    }

    // RHS - QR icon
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 12, 76, 12);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* fill;
        gui_make_fill(&fill, TFT_BLACK);
        gui_set_parent(fill, vsplit);

        // QR icon background
        gui_make_fill(&fill, GUI_BLOCKSTREAM_QR_PALE);
        gui_set_parent(fill, vsplit);

        gui_make_icon(&node, qr_icon, TFT_BLACK, &GUI_BLOCKSTREAM_QR_PALE);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, fill);
        gui_set_icon_animation(node, qr_icon, 1, 0); // takes ownership of icon

        gui_make_fill(&fill, TFT_BLACK);
        gui_set_parent(fill, vsplit);
    }

    return act;
}
