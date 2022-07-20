#include "../button_events.h"
#include "../gui.h"
#include "../jade_assert.h"

// Generic activity that displays a message, optionally with an 'ok' button
static void make_msg_activity(gui_activity_t** activity_ptr, const char* msg, const bool error, const bool button)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(msg);

    gui_make_activity(activity_ptr, false, NULL);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, msg, error ? TFT_RED : TFT_WHITE);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text, vsplit);

    if (button) {
        gui_view_node_t* btn;
        gui_make_button(&btn, TFT_BLACK, BTN_EXIT_MESSAGE_SCREEN, NULL);
        gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 4, 85);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* txt;
        gui_make_text(&txt, "Ok", TFT_WHITE);
        gui_set_parent(txt, btn);
        gui_set_align(txt, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }
}

// Generic activity that displays a message on two lines, optionally with an 'ok' button
static void make_msg_activity_two_lines(
    gui_activity_t** activity_ptr, const char* msg_first, const char* msg_second, const bool error, const bool button)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(msg_first);
    JADE_ASSERT(msg_second);

    gui_make_activity(activity_ptr, false, NULL);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 35, 35, 30);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
        gui_make_button(&btn, TFT_BLACK, BTN_EXIT_MESSAGE_SCREEN, NULL);
        gui_set_margins(btn, GUI_MARGIN_TWO_VALUES, 4, 85);
        gui_set_borders(btn, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn, vsplit);

        gui_view_node_t* txt;
        gui_make_text(&txt, "Ok", TFT_WHITE);
        gui_set_parent(txt, btn);
        gui_set_align(txt, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }
}

// Run generic activity that displays a message and awaits a button click
static void await_msg_activity(const char* msg, const bool error)
{
    gui_activity_t* activity = NULL;
    make_msg_activity(&activity, msg, error, true);
    JADE_ASSERT(activity);

    gui_set_current_activity(activity);

    // Display the message and wait for the user to press the button
    // In a debug unatteneded ci build, assume button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_EXIT_MESSAGE_SCREEN, NULL, NULL, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS);
    const bool ret = true;
#endif
    JADE_ASSERT_MSG(ret, "gui_activity_wait_event returned %d", ret);
}

// Run generic activity that displays a message (no button or awaiting click)
// Returns the activity to the caller.
gui_activity_t* display_message_activity(const char* message)
{
    gui_activity_t* activity = NULL;
    make_msg_activity(&activity, message, false, false);
    JADE_ASSERT(activity);

    gui_set_current_activity(activity);
    return activity;
}

// Run generic activity that displays a message on two lines (no button or awaiting click)
// Returns the activity to the caller.
gui_activity_t* display_message_activity_two_lines(const char* msg_first, const char* msg_second)
{
    gui_activity_t* activity = NULL;
    make_msg_activity_two_lines(&activity, msg_first, msg_second, false, false);
    JADE_ASSERT(activity);

    gui_set_current_activity(activity);
    return activity;
}

// Run generic activity that displays a message and awaits a button click
void await_message_activity(const char* message) { await_msg_activity(message, false); }

// Run generic activity that displays an error msg and awaits a button click
void await_error_activity(const char* errormessage) { await_msg_activity(errormessage, true); }

// Generic activity that displays a message and Yes/No buttons.
static void make_yesno_activity(
    gui_activity_t** activity_ptr, const char* title, const char* message, const bool default_selection)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(message);
    // title is optional

    gui_make_activity(activity_ptr, title, title);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 66, 34);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // First row, message text
    gui_view_node_t* text;
    gui_make_text(&text, message, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 8);
    gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, Yes and No buttons
    gui_view_node_t* hsplit = NULL;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, vsplit);

    // No
    gui_view_node_t* btnNo;
    gui_make_button(&btnNo, TFT_BLACK, BTN_NO, NULL);
    gui_set_margins(btnNo, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btnNo, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btnNo, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btnNo, hsplit);

    gui_view_node_t* txtNo;
    gui_make_text(&txtNo, "No", TFT_WHITE);
    gui_set_parent(txtNo, btnNo);
    gui_set_align(txtNo, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Yes
    gui_view_node_t* btnYes;
    gui_make_button(&btnYes, TFT_BLACK, BTN_YES, NULL);
    gui_set_margins(btnYes, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btnYes, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btnYes, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btnYes, hsplit);

    gui_view_node_t* txtYes;
    gui_make_text(&txtYes, "Yes", TFT_WHITE);
    gui_set_parent(txtYes, btnYes);
    gui_set_align(txtYes, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Select default button
    gui_set_activity_initial_selection(*activity_ptr, default_selection ? btnYes : btnNo);
}

// Run generic activity that displays a message and Yes/No buttons, and waits
// for button press.  Function returns true if 'Yes' was pressed.
bool await_yesno_activity(const char* title, const char* message, const bool default_selection)
{
    JADE_ASSERT(message);
    // title is optional

    gui_activity_t* activity = NULL;
    make_yesno_activity(&activity, title, message, default_selection);
    JADE_ASSERT(activity);

    // Display and wait for button press
    gui_set_current_activity(activity);

    // In a debug unattended ci build, assume 'Yes' button pressed after a short delay
    int32_t ev_id = ESP_EVENT_ANY_ID;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS);
    const bool ret = true;
    ev_id = BTN_YES;
#endif
    JADE_ASSERT_MSG(ret, "gui_activity_wait_event returned %d", ret);

    // Return true if 'Yes' was pressed
    return ev_id == BTN_YES;
}

// Show a progress bar screen, with the given title.
// The progress-bar structure indicated is populated, and should be used to update the progress
// using the update_progress_bar() function below.
void display_progress_bar_activity(const char* title, const char* message, progress_bar_t* progress_bar)
{
    JADE_ASSERT(progress_bar);
    JADE_ASSERT(message);
    // title is optional

    gui_activity_t* act = NULL;
    gui_make_activity(&act, title, title);

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
    gui_view_node_t* container;
    gui_make_fill(&container, TFT_BLACK);
    gui_set_borders(container, TFT_WHITE, 2, GUI_BORDER_ALL);
    gui_set_margins(container, GUI_MARGIN_TWO_VALUES, 4, 16);
    gui_set_parent(container, vsplit);

    gui_view_node_t* progress;
    gui_make_fill(&progress, TFT_BLACK);
    gui_set_margins(progress, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(progress, TFT_BLOCKSTREAM_GREEN, 0, GUI_BORDER_LEFT);
    gui_set_parent(progress, container);

    // third row, percentage text
    gui_view_node_t* background;
    gui_make_fill(&background, TFT_BLACK);
    gui_set_parent(background, vsplit);

    gui_view_node_t* pcnt;
    gui_make_text(&pcnt, "0%", TFT_WHITE);
    gui_set_parent(pcnt, background);
    gui_set_padding(pcnt, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(pcnt, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // Display the progress bar
    gui_set_current_activity(act);

    // Populate the struct for the caller to pass into the update function below
    progress_bar->progress_bar = progress;
    progress_bar->pcnt_txt = pcnt;
}

void update_progress_bar(progress_bar_t* progress_bar, const size_t total, const size_t current)
{
    JADE_ASSERT(progress_bar);
    JADE_ASSERT(progress_bar->progress_bar);
    JADE_ASSERT(progress_bar->pcnt_txt);
    JADE_ASSERT(current <= total);
    JADE_ASSERT(total > 0);
    JADE_ASSERT(progress_bar->percent_last_value >= 0 && progress_bar->percent_last_value <= 100);

    const uint8_t pcnt = 100 * current / total;
    if (pcnt == progress_bar->percent_last_value) {
        // percentage hasn't changed, skip update
        return;
    }

    if (!progress_bar->progress_bar->render_data.is_first_time) {
        // Can only reliably update the progress bar after it's initial rendering
        const dispWin_t* constraints = &progress_bar->progress_bar->render_data.original_constraints;
        const gui_margin_t* margins = &progress_bar->progress_bar->margins;
        const uint16_t width_bar = constraints->x2 - constraints->x1 - margins->left - margins->right;
        const uint16_t width_shaded = width_bar * current / total;
        gui_set_borders(progress_bar->progress_bar, TFT_BLOCKSTREAM_GREEN, width_shaded, GUI_BORDER_LEFT);
        gui_repaint(progress_bar->progress_bar, true);
    }

    char text[8];
    const int ret = snprintf(text, sizeof(text), "%u%%", pcnt);
    JADE_ASSERT(ret > 0 && ret < sizeof(text));
    gui_update_text(progress_bar->pcnt_txt, text);
    progress_bar->percent_last_value = pcnt;
}
