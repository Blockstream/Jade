#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void make_show_qr_help_activity(gui_activity_t** activity_ptr, const char* url, const Icon* qr_icon)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(url);
    JADE_ASSERT(qr_icon);
    JADE_ASSERT(qr_icon->width <= 100);
    JADE_ASSERT(qr_icon->height <= 100);

    gui_make_activity(activity_ptr, false, NULL);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 56, 44);
    gui_set_parent(hsplit, (*activity_ptr)->root_node);

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
        gui_set_padding(text_url, GUI_MARGIN_TWO_VALUES, 2, 2);
        gui_set_align(text_url, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

        // buttons, back
        btn_data_t btn = { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_EXIT_QR_HELP };
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
        gui_make_fill(&bg_fill_node, TFT_DARKGREY);
        gui_set_parent(bg_fill_node, vsplit);

        gui_view_node_t* icon_node;
        gui_make_icon(&icon_node, qr_icon, TFT_BLACK, &TFT_DARKGREY);
        gui_set_align(icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(icon_node, bg_fill_node);

        gui_view_node_t* lower;
        gui_make_fill(&lower, TFT_BLACK);
        gui_set_parent(lower, vsplit);
    }
}
