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

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 42, 58);
    gui_set_parent(hsplit, act->root_node);

    // LHS
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 19, 19, 46);
    gui_set_parent(vsplit, hsplit);

    // first row, header
    gui_view_node_t* title;
    gui_make_text(&title, "Xpub Export", TFT_WHITE);
    gui_set_parent(title, vsplit);
    gui_set_padding(title, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_align(title, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(title, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    // second row, type label
    gui_view_node_t* text;
    gui_make_text(&text, label, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // third row, path
    gui_view_node_t* path;
    gui_make_text(&path, pathstr, TFT_WHITE);
    gui_set_parent(path, vsplit);
    gui_set_padding(path, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_align(path, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // buttons
    btn_data_t btns[] = { { .txt = "Options", .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_XPUB_EXIT } };
    add_buttons(vsplit, UI_COLUMN, btns, 2);

    // Select 'exit' as the default button
    gui_set_activity_initial_selection(act, btns[1].btn);

    // RHS - QR icons
    gui_view_node_t* bg_fill_node;
    gui_make_fill(&bg_fill_node, TFT_BLOCKSTREAM_QR_PALE);
    gui_set_parent(bg_fill_node, hsplit);

    gui_view_node_t* icon_node;
    gui_make_icon(&icon_node, icons, TFT_BLACK, &TFT_BLOCKSTREAM_QR_PALE);
    gui_set_align(icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(icon_node, bg_fill_node);
    gui_set_icon_animation(icon_node, icons, num_icons, frames_per_qr_icon);

    return act;
}

gui_activity_t* make_xpub_qr_options_activity(
    gui_view_node_t** script_textbox, gui_view_node_t** multisig_textbox, gui_view_node_t** urtype_textbox)
{
    JADE_INIT_OUT_PPTR(script_textbox);
    JADE_INIT_OUT_PPTR(multisig_textbox);
    JADE_INIT_OUT_PPTR(urtype_textbox);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 24, 24, 24, 28);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Script Type", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_XPUB_TOGGLE_SCRIPT, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *script_textbox = text;
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Wallet Type", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_XPUB_TOGGLE_MULTISIG, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *multisig_textbox = text;
    }

    /*  Not currently in use
        {
            gui_view_node_t* hsplit;
            gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
            gui_set_parent(hsplit, vsplit);

            gui_view_node_t* key;
            gui_make_text(&key, "UR Type", TFT_WHITE);
            gui_set_parent(key, hsplit);
            gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_XPUB_TOGGLE_BCUR_TYPE, NULL);
            gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_RED);
            gui_set_parent(btn, hsplit);

            gui_view_node_t* text;
            gui_make_text(&text, "", TFT_WHITE);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(text, btn);
            *urtype_textbox = text;
        }
        */
    {
        gui_view_node_t* filler;
        gui_make_fill(&filler, TFT_BLACK);
        gui_set_parent(filler, vsplit);
    }

    // buttons
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_XPUB_OPTIONS_EXIT },
        { .txt = "?", .font = GUI_DEFAULT_FONT, .ev_id = BTN_XPUB_OPTIONS_HELP } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    return act;
}

gui_activity_t* make_search_verify_address_activity(
    const char* root_label, progress_bar_t* progress_bar, gui_view_node_t** index_text)
{
    JADE_ASSERT(progress_bar);
    JADE_ASSERT(index_text);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 24, 24, 24, 28);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 20, 80);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* label;
        gui_make_text(&label, "Root:", TFT_WHITE);
        gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_padding(label, GUI_MARGIN_TWO_VALUES, 0, 4);
        gui_set_parent(label, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, root_label, TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, hsplit);
    }

    // Progress bar
    make_progress_bar(vsplit, progress_bar);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* label;
        gui_make_text(&label, "Current Index:", TFT_WHITE);
        gui_set_align(label, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_padding(label, GUI_MARGIN_TWO_VALUES, 0, 4);
        gui_set_parent(label, hsplit);

        gui_view_node_t* bg_fill;
        gui_make_fill(&bg_fill, TFT_BLACK);
        gui_set_parent(bg_fill, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, bg_fill);
        *index_text = text;
    }

    // buttons
    btn_data_t btns[] = { { .txt = "Exit", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SCAN_ADDRESS_EXIT },
        { .txt = "Skip", .font = GUI_DEFAULT_FONT, .ev_id = BTN_SCAN_ADDRESS_SKIP_ADDRESSES } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    // Select 'Skip' button by default
    gui_set_activity_initial_selection(act, btns[1].btn);

    return act;
}

gui_activity_t* make_qr_options_activity(gui_view_node_t** density_textbox, gui_view_node_t** speed_textbox)
{
    JADE_INIT_OUT_PPTR(density_textbox);
    JADE_INIT_OUT_PPTR(speed_textbox);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 24, 24, 24, 28);
    gui_set_parent(vsplit, act->root_node);

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "QR Density", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_QR_TOGGLE_DENSITY, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *density_textbox = text;
    }

    {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
        gui_set_parent(hsplit, vsplit);

        gui_view_node_t* key;
        gui_make_text(&key, "Frame Rate", TFT_WHITE);
        gui_set_parent(key, hsplit);
        gui_set_align(key, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_QR_TOGGLE_SPEED, NULL);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_RED);
        gui_set_parent(btn, hsplit);

        gui_view_node_t* text;
        gui_make_text(&text, "", TFT_WHITE);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(text, btn);
        *speed_textbox = text;
    }

    {
        gui_view_node_t* filler;
        gui_make_fill(&filler, TFT_BLACK);
        gui_set_parent(filler, vsplit);
    }

    // buttons
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_OPTIONS_EXIT },
        { .txt = "?", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS_HELP } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    return act;
}

// NOTE: 'icons' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_show_qr_activity(const char* title, const char* label, Icon* icons, const size_t num_icons,
    const size_t frames_per_qr_icon, const bool show_options_button)
{
    JADE_ASSERT(title);
    JADE_ASSERT(label);
    JADE_ASSERT(icons);
    JADE_ASSERT(num_icons);
    JADE_ASSERT(frames_per_qr_icon || num_icons == 1);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 42, 58);
    gui_set_parent(hsplit, act->root_node);

    // LHS
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 16, 38, 46);
    gui_set_parent(vsplit, hsplit);

    // first row, header
    gui_view_node_t* txt_title;
    gui_make_text(&txt_title, title, TFT_WHITE);
    gui_set_parent(txt_title, vsplit);
    gui_set_padding(txt_title, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_align(txt_title, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(txt_title, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    // second row, type label
    gui_view_node_t* text;
    gui_make_text(&text, label, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 0, 2);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // Buttons - 'options' and  back/exit, or just back/exit
    if (show_options_button) {
        btn_data_t btns[] = { { .txt = "Options", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_OPTIONS },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_QR_DISPLAY_EXIT } };
        add_buttons(vsplit, UI_COLUMN, btns, 2);

        // Select 'exit' as the default button
        gui_set_activity_initial_selection(act, btns[1].btn);
    } else {
        btn_data_t btns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_QR_DISPLAY_EXIT } };
        add_buttons(vsplit, UI_COLUMN, btns, 2);
    }

    // RHS - QR icons
    gui_view_node_t* bg_fill_node;
    gui_make_fill(&bg_fill_node, TFT_BLOCKSTREAM_QR_PALE);
    gui_set_parent(bg_fill_node, hsplit);

    gui_view_node_t* icon_node;
    gui_make_icon(&icon_node, icons, TFT_BLACK, &TFT_BLOCKSTREAM_QR_PALE);
    gui_set_align(icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(icon_node, bg_fill_node);
    gui_set_icon_animation(icon_node, icons, num_icons, frames_per_qr_icon);

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

    // LHS
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 32, 28, 24);
        gui_set_parent(vsplit, hsplit);

        // first row, header
        gui_view_node_t* title;
        gui_make_text(&title, "Learn More", TFT_WHITE);
        gui_set_parent(title, vsplit);
        gui_set_padding(title, GUI_MARGIN_TWO_VALUES, 0, 2);
        gui_set_align(title, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_borders(title, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

        // second row, message
        gui_view_node_t* text;
        gui_make_text(&text, "Scan QR or visit\nlink to learn more", TFT_WHITE);
        gui_set_parent(text, vsplit);
        gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 0);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_LEFT);

        // third row, url
        gui_view_node_t* text_url;
        gui_make_text(&text_url, url, TFT_WHITE);
        gui_set_parent(text_url, vsplit);
        gui_set_padding(text_url, GUI_MARGIN_ALL_DIFFERENT, 2, 4, 0, 2);
        gui_set_align(text_url, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

        // buttons, done
        btn_data_t btn = { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_EXIT_QR_HELP };
        add_buttons(vsplit, UI_COLUMN, &btn, 1);
    }

    // RHS - QR icon
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 16, 76, 8);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* upper;
        gui_make_fill(&upper, TFT_BLACK);
        gui_set_parent(upper, vsplit);

        gui_view_node_t* bg_fill_node;
        gui_make_fill(&bg_fill_node, TFT_BLOCKSTREAM_QR_PALE);
        gui_set_parent(bg_fill_node, vsplit);

        gui_view_node_t* icon_node;
        gui_make_icon(&icon_node, qr_icon, TFT_BLACK, &TFT_BLOCKSTREAM_QR_PALE);
        gui_set_align(icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(icon_node, bg_fill_node);
        gui_set_icon_animation(icon_node, qr_icon, 1, 0); // takes ownership of icon

        gui_view_node_t* lower;
        gui_make_fill(&lower, TFT_BLACK);
        gui_set_parent(lower, vsplit);
    }

    return act;
}

// NOTE: 'qr_icon' passed in here must be heap-allocated as the gui element takes ownership
gui_activity_t* make_show_qr_yesno_activity(
    const char* title, const char* label, const char* url, Icon* qr_icon, const bool default_selection)
{
    JADE_ASSERT(title);
    JADE_ASSERT(label);
    JADE_ASSERT(qr_icon);
    JADE_ASSERT(qr_icon->width <= 100);
    JADE_ASSERT(qr_icon->height <= 100);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 56, 44);
    gui_set_parent(hsplit, act->root_node);

    // LHS
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 32, 28, 24);
        gui_set_parent(vsplit, hsplit);

        // first row, header
        gui_view_node_t* text_title;
        gui_make_text(&text_title, title, TFT_WHITE);
        gui_set_parent(text_title, vsplit);
        gui_set_padding(text_title, GUI_MARGIN_TWO_VALUES, 0, 2);
        gui_set_align(text_title, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_borders(text_title, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

        // second row, message
        gui_view_node_t* text_label;
        gui_make_text(&text_label, label, TFT_WHITE);
        gui_set_parent(text_label, vsplit);
        gui_set_padding(text_label, GUI_MARGIN_TWO_VALUES, 8, 0);
        gui_set_align(text_label, GUI_ALIGN_CENTER, GUI_ALIGN_LEFT);

        // third row, url
        gui_view_node_t* text_url;
        gui_make_text(&text_url, url, TFT_WHITE);
        gui_set_parent(text_url, vsplit);
        gui_set_padding(text_url, GUI_MARGIN_TWO_VALUES, 2, 2);
        gui_set_align(text_url, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

        // buttons, done
        btn_data_t btns[] = { { .txt = "X", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_YES } };
        add_buttons(vsplit, UI_ROW, btns, 2);

        // Select default button
        gui_set_activity_initial_selection(act, default_selection ? btns[1].btn : btns[0].btn);
    }

    // RHS - QR icon
    {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 16, 76, 8);
        gui_set_parent(vsplit, hsplit);

        gui_view_node_t* upper;
        gui_make_fill(&upper, TFT_BLACK);
        gui_set_parent(upper, vsplit);

        gui_view_node_t* bg_fill_node;
        gui_make_fill(&bg_fill_node, TFT_BLOCKSTREAM_QR_PALE);
        gui_set_parent(bg_fill_node, vsplit);

        gui_view_node_t* icon_node;
        gui_make_icon(&icon_node, qr_icon, TFT_BLACK, &TFT_BLOCKSTREAM_QR_PALE);
        gui_set_align(icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(icon_node, bg_fill_node);
        gui_set_icon_animation(icon_node, qr_icon, 1, 0); // takes ownership of icon

        gui_view_node_t* lower;
        gui_make_fill(&lower, TFT_BLACK);
        gui_set_parent(lower, vsplit);
    }

    return act;
}
