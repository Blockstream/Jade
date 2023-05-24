#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

// Helper to update dynamic menu item label (name: value)
void update_menu_item(gui_view_node_t* node, const char* label, const char* value)
{
    char buf[32];
    const int ret = snprintf(buf, sizeof(buf), "%s: %s", label, value);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    gui_update_text(node, buf);
}

// Helper to make a standard button, for consistent look and feel behaviour
void add_button(gui_view_node_t* parent, btn_data_t* btn_info)
{
    JADE_ASSERT(parent);
    JADE_ASSERT(btn_info);

    gui_view_node_t* btn;

    // No event implies no 'pressable' button in this position - use a 'fill' instead
    if (btn_info->ev_id == GUI_BUTTON_EVENT_NONE) {
        gui_make_fill(&btn, TFT_BLACK);
    } else {
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, btn_info->ev_id, NULL);
        gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
    }
    gui_set_parent(btn, parent);

    // Add any text
    if (btn_info->txt) {
        gui_view_node_t* text;
        gui_make_text_font(&text, btn_info->txt, TFT_WHITE, btn_info->font);
        gui_set_parent(text, btn);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }

    // Set the (btn) control back in the info struct
    btn_info->btn = btn;
}

// Helper to create up to four buttons in a row or column
void add_buttons(gui_view_node_t* parent, const ui_button_layout_t layout, btn_data_t* btns, const size_t num_btns)
{
    JADE_ASSERT(parent);
    JADE_ASSERT(layout == UI_ROW || layout == UI_COLUMN);
    JADE_ASSERT(btns);
    JADE_ASSERT(num_btns);
    JADE_ASSERT(num_btns <= 4);

    if (num_btns == 1) {
        // skip intermediate split, apply button directly to parent
        // ('layout' (row or column) is irrelevant in this case)
        add_button(parent, btns);
        return;
    }

    // Make the split relevant for the number of buttons
    typedef void (*make_split_fn)(gui_view_node_t * *ptr, enum gui_split_type kind, uint32_t parts, ...);
    make_split_fn make_split = (layout == UI_COLUMN) ? gui_make_vsplit : gui_make_hsplit;

    // Make a split for the number of buttons (if greater than one)
    gui_view_node_t* split = NULL;
    switch (num_btns) {
    case 2:
        make_split(&split, GUI_SPLIT_RELATIVE, 2, 50, 50);
        break;
    case 3:
        make_split(&split, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
        break;
    case 4:
        make_split(&split, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
        break;
    default:
        JADE_ASSERT_MSG(false, "Unsupported number of buttons");
    }
    gui_set_parent(split, parent);

    // Add buttons to split
    for (size_t i = 0; i < num_btns; ++i) {
        add_button(split, btns + i);
    }
}

// activity to show a single central label, which can be updated by the caller
gui_activity_t* make_show_label_activity(const char* title, const char* message, gui_view_node_t** item_text)
{
    // title is optional
    JADE_ASSERT(message);
    JADE_INIT_OUT_PPTR(item_text);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 40, 60);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text_message;
    gui_make_text(&text_message, message, TFT_WHITE);
    gui_set_padding(text_message, GUI_MARGIN_TWO_VALUES, 4, 4);
    gui_set_align(text_message, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_message, vsplit);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 12, 76, 12);
    gui_set_padding(hsplit, GUI_MARGIN_TWO_VALUES, 8, 0);
    gui_set_parent(hsplit, vsplit);

    // Left arrow
    gui_view_node_t* text_left;
    gui_make_text_font(&text_left, "=", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_left, GUI_ALIGN_RIGHT, GUI_ALIGN_TOP);
    gui_set_parent(text_left, hsplit);

    // Updateable label
    gui_view_node_t* bg_fill;
    gui_make_fill(&bg_fill, TFT_BLACK);
    gui_set_parent(bg_fill, hsplit);

    gui_view_node_t* text_label;
    gui_make_text(&text_label, message, TFT_WHITE);
    gui_set_align(text_label, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    gui_set_parent(text_label, bg_fill);
    *item_text = text_label;

    // Right arrow
    gui_view_node_t* text_right;
    gui_make_text_font(&text_right, ">", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_right, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_parent(text_right, hsplit);

    return act;
}

// Generic activity that displays a message, optionally with an 'ok' button
static gui_activity_t* make_msg_activity(const char* msg, const bool error, const bool button)
{
    JADE_ASSERT(msg);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, msg, error ? TFT_RED : TFT_WHITE);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text, vsplit);

    if (button) {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_EXIT_MESSAGE_SCREEN, NULL);
        gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 4, 85);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* txt;
        gui_make_text(&txt, "Ok", TFT_WHITE);
        gui_set_parent(txt, btn);
        gui_set_align(txt, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }

    return act;
}

// Generic activity that displays a message on two lines, optionally with an 'ok' button
static gui_activity_t* make_msg_activity_two_lines(
    const char* msg_first, const char* msg_second, const bool error, const bool button)
{
    JADE_ASSERT(msg_first);
    JADE_ASSERT(msg_second);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 35, 35, 30);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text_first;
    gui_make_text(&text_first, msg_first, error ? TFT_RED : TFT_WHITE);
    gui_set_padding(text_first, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_align(text_first, GUI_ALIGN_CENTER, GUI_ALIGN_BOTTOM);
    gui_set_parent(text_first, vsplit);

    gui_view_node_t* text_second;
    gui_make_text(&text_second, msg_second, error ? TFT_RED : TFT_WHITE);
    gui_set_padding(text_second, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_align(text_second, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    gui_set_parent(text_second, vsplit);

    if (button) {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, BTN_EXIT_MESSAGE_SCREEN, NULL);
        gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 4, 85);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* txt;
        gui_make_text(&txt, "Ok", TFT_WHITE);
        gui_set_parent(txt, btn);
        gui_set_align(txt, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }

    return act;
}

// Run generic activity that displays a message and awaits a button click
static void await_msg_activity(const char* msg, const bool error)
{
    gui_activity_t* const act = make_msg_activity(msg, error, true);
    gui_set_current_activity(act);

    // Display the message and wait for the user to press the button
    // In a debug unatteneded ci build, assume button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_EXIT_MESSAGE_SCREEN, NULL, NULL, NULL, 0);
#else
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_EXIT_MESSAGE_SCREEN, NULL, NULL, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
#endif
    JADE_ASSERT_MSG(ret, "gui_activity_wait_event returned %d", ret);
}

// Run generic activity that displays a message (no button or awaiting click)
// Returns the activity to the caller.
gui_activity_t* display_message_activity(const char* message)
{
    gui_activity_t* const act = make_msg_activity(message, false, false);
    gui_set_current_activity(act);
    return act;
}

// Run generic activity that displays a message on two lines (no button or awaiting click)
// Returns the activity to the caller.
gui_activity_t* display_message_activity_two_lines(const char* msg_first, const char* msg_second)
{
    gui_activity_t* const act = make_msg_activity_two_lines(msg_first, msg_second, false, false);
    gui_set_current_activity(act);
    return act;
}

// Run generic activity that displays a message and awaits a button click
void await_message_activity(const char* message) { await_msg_activity(message, false); }

// Run generic activity that displays an error msg and awaits a button click
void await_error_activity(const char* errormessage) { await_msg_activity(errormessage, true); }

// Generic activity that displays a message and Yes/No buttons.
static gui_activity_t* make_yesno_activity(const char* title, const char* message, const bool default_selection)
{
    JADE_ASSERT(message);
    // title is optional

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 68, 32);
    gui_set_parent(vsplit, act->root_node);

    // First row, message text
    gui_view_node_t* text;
    gui_make_text(&text, message, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 4, 8);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, Yes and No buttons
    btn_data_t btns[] = { { .txt = "No", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO },
        { .txt = "Yes", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    // Select default button
    gui_set_activity_initial_selection(act, default_selection ? btns[1].btn : btns[0].btn);

    return act;
}

// Run generic activity that displays a message and Yes/No buttons, and waits
// for button press.  Function returns true if 'Yes' was pressed.
bool await_yesno_activity(const char* title, const char* message, const bool default_selection)
{
    JADE_ASSERT(message);
    // title is optional

    gui_activity_t* const act = make_yesno_activity(title, message, default_selection);
    gui_set_current_activity(act);

    // In a debug unattended ci build, assume 'Yes' button pressed after a short delay
    int32_t ev_id = ESP_EVENT_ANY_ID;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
    ev_id = BTN_YES;
#endif
    JADE_ASSERT_MSG(ret, "gui_activity_wait_event returned %d", ret);

    // Return true if 'Yes' was pressed
    return ev_id == BTN_YES;
}

// The progress-bar structure indicated is populated, and should be used to update the progress
// using the update_progress_bar() function below.
void make_progress_bar(gui_view_node_t* parent, progress_bar_t* progress_bar)
{
    gui_view_node_t* container;
    gui_make_fill(&container, TFT_BLACK);
    gui_set_borders(container, TFT_WHITE, 2, GUI_BORDER_ALL);
    gui_set_margins(container, GUI_MARGIN_TWO_VALUES, 4, 16);
    gui_set_parent(container, parent);

    gui_view_node_t* progress;
    gui_make_fill(&progress, TFT_BLACK);
    gui_set_margins(progress, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(progress, TFT_BLOCKSTREAM_GREEN, 0, GUI_BORDER_LEFT);
    gui_set_parent(progress, container);

    progress_bar->progress_bar = progress;
}

// Create a progress bar screen, with the given title.
// The progress-bar structure indicated is populated, and should be used to update the progress
// using the update_progress_bar() function below.
gui_activity_t* make_progress_bar_activity(const char* title, const char* message, progress_bar_t* progress_bar)
{
    JADE_ASSERT(progress_bar);
    JADE_ASSERT(message);
    // title is optional

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 26, 44, 30);
    gui_set_parent(vsplit, act->root_node);

    // First row, message text
    gui_view_node_t* text;
    gui_make_text(&text, message, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, progress bar
    make_progress_bar(vsplit, progress_bar);

    // third row, percentage text
    gui_view_node_t* background;
    gui_make_fill(&background, TFT_BLACK);
    gui_set_parent(background, vsplit);

    gui_view_node_t* pcnt;
    gui_make_text(&pcnt, "0%", TFT_WHITE);
    gui_set_parent(pcnt, background);
    gui_set_padding(pcnt, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(pcnt, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    progress_bar->pcnt_txt = pcnt;

    return act;
}

void update_progress_bar(progress_bar_t* progress_bar, const size_t total, const size_t current)
{
    JADE_ASSERT(progress_bar);
    JADE_ASSERT(progress_bar->progress_bar);
    // progress_bar->pcnt_txt is optional

    JADE_ASSERT(current <= total);
    JADE_ASSERT(total > 0);
    JADE_ASSERT(progress_bar->percent_last_value <= 100);

    const uint8_t pcnt = 100 * current / total;
    if (pcnt == progress_bar->percent_last_value) {
        // percentage hasn't changed, skip update
        return;
    }

    if (!progress_bar->progress_bar->render_data.is_first_time) {
        // Can only reliably update the progress bar after its initial rendering
        const uint16_t constraints_x1 = progress_bar->progress_bar->render_data.original_constraints.x1;
        const uint16_t constraints_x2 = progress_bar->progress_bar->render_data.original_constraints.x2;
        const gui_margin_t* const margins = &progress_bar->progress_bar->margins;
        const uint16_t width_bar = constraints_x2 - constraints_x1 - margins->left - margins->right;
        const uint16_t width_shaded = width_bar * current / total;

        gui_set_borders(progress_bar->progress_bar, TFT_BLOCKSTREAM_GREEN, width_shaded, GUI_BORDER_LEFT);
        gui_repaint(progress_bar->progress_bar, true);
    }

    // Update the % progress text label if present
    if (progress_bar->pcnt_txt) {
        char text[8];
        const int ret = snprintf(text, sizeof(text), "%u%%", pcnt);
        JADE_ASSERT(ret > 0 && ret < sizeof(text));
        gui_update_text(progress_bar->pcnt_txt, text);
    }

    progress_bar->percent_last_value = pcnt;
}
