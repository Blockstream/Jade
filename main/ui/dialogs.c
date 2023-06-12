#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void await_qr_help_activity(const char* url);

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

    // Cannot specify both 'text label' and 'explicit content'
    JADE_ASSERT(!btn_info->txt || !btn_info->content);

    gui_view_node_t* btn;

    // No event implies no 'pressable' button in this position - use a 'fill' instead
    if (btn_info->ev_id == GUI_BUTTON_EVENT_NONE) {
        gui_make_fill(&btn, TFT_BLACK);
    } else {
        gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, btn_info->ev_id, NULL);
    }
    gui_set_parent(btn, parent);

    // If borders explcitly specified, show in dark grey
    // 0 implies default behaviour - no visible borders when not selected
    if (btn_info->borders) {
        gui_set_borders(btn, TFT_BLOCKSTREAM_BUTTONBORDER_GREY, 1, btn_info->borders);
    } else {
        gui_set_borders(btn, TFT_BLACK, 1, GUI_BORDER_ALL);
    }

    // In any case green body/bg when selected
    gui_set_colors(btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN);

    // Add any simple text label
    if (btn_info->txt) {
        gui_view_node_t* text;
        gui_make_text_font(&text, btn_info->txt, TFT_WHITE, btn_info->font);
        gui_set_parent(text, btn);
        gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    } else if (btn_info->content) {
        // In more complex cases caller can prepare content and pass instead
        gui_set_parent(btn_info->content, btn);
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

static inline btn_data_t* add_default_border(btn_data_t* btn, const uint32_t default_borders)
{
    if (!btn->borders && btn->ev_id != GUI_BUTTON_EVENT_NONE) {
        btn->borders = default_borders;
    }
    return btn;
}

// Helper to populate the common title bar
void populate_title_bar(
    gui_view_node_t* bar, const char* title, btn_data_t* btns, const size_t num_btns, gui_view_node_t** title_node)
{
    JADE_ASSERT(bar);
    JADE_ASSERT(title || btns);
    JADE_ASSERT((btns && num_btns == 2) || !num_btns);
    JADE_ASSERT(!title_node || title);
    // title is optional but do not expect neither title nor buttons
    // buttons are optional, but must have zero or two (can be placeholder)
    // title_node is optional, but can only be passed if a title (even an empty string) is passed

    // Create the title text
    // If the caller has asked for the node to be returned it probably means they are expecting
    // to update it - in which case inject an intermediate fill (so updated text redraws properly).
    gui_view_node_t* titlenode;
    if (title) {
        gui_make_text_font(&titlenode, title, TFT_WHITE, GUI_TITLE_FONT);
        gui_set_align(titlenode, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

        if (title_node) {
            *title_node = titlenode;
            gui_make_fill(&titlenode, TFT_BLACK);
            gui_set_parent(*title_node, titlenode);
        }
    } else {
        // No title, just a blank space
        gui_make_fill(&titlenode, TFT_BLACK);
    }

    if (!num_btns) {
        // Just a title, no buttons - just apply straight to the bar node
        gui_set_parent(titlenode, bar);
    } else {
        // Split the bar into three sections, [lbtn | title | rbtn]
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 15, 70, 15);
        gui_set_parent(hsplit, bar);

        // If not otherwise specified, put a border around the buttons
        add_button(hsplit, add_default_border(btns, GUI_BORDER_ALL));
        gui_set_parent(titlenode, hsplit);
        add_button(hsplit, add_default_border(btns + 1, GUI_BORDER_ALL));
    }
}

// Helper to create and populate the common title bar
gui_view_node_t* add_title_bar(
    gui_activity_t* activity, const char* title, btn_data_t* btns, const size_t num_btns, gui_view_node_t** title_node)
{
    JADE_ASSERT(activity);

    // Split off the top 20% as the title bar
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 20, 80);
    gui_set_parent(vsplit, activity->root_node);

    // Populate the title bar
    populate_title_bar(vsplit, title, btns, num_btns, title_node);

    // Return the new parent for further ui elements
    return vsplit;
}

// Helper to create an activity to show a vertical menu
// Must pass title-bar information - supports 2, 3 or 4 menu buttons
gui_activity_t* make_menu_activity(
    const char* title, btn_data_t* hdrbtns, const size_t num_hdrbtns, btn_data_t* menubtns, const size_t num_menubtns)
{
    JADE_ASSERT(title);
    // Header buttons are optional
    JADE_ASSERT(menubtns);
    JADE_ASSERT(num_menubtns > 1);
    JADE_ASSERT(num_menubtns < 5);

    // Explicitly set just left|top|right borders around header buttons when menu is 'full'
    // as bottom edge will be covered by upper line above top menu item.
    if (num_menubtns > 2) {
        for (size_t i = 0; i < num_hdrbtns; ++i) {
            add_default_border(&hdrbtns[i], GUI_BORDER_SIDES | GUI_BORDER_TOP);
        }
    }

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(act, title, hdrbtns, num_hdrbtns, NULL);

    // Add any padding for smaller number of items
    if (num_menubtns == 2) {
        gui_view_node_t* vsplit;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 65, 35);
        gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 12, 0, 0, 0);
        gui_set_parent(vsplit, parent);
        parent = vsplit;
    }

    // Add default borders between menu items
    for (size_t i = 0; i < num_menubtns; ++i) {
        add_default_border(&menubtns[i], i == 0 ? GUI_BORDER_TOPBOTTOM : GUI_BORDER_BOTTOM);
    }

    // Add menu buttons
    add_buttons(parent, UI_COLUMN, menubtns, num_menubtns);

    return act;
}

// Helper to create an activity to show a message on a single central label
// Can pass title-bar information (optional) and footer buttons (also optional)
gui_activity_t* make_show_message_activity(const char* message, const uint32_t toppad, const char* title,
    btn_data_t* hdrbtns, const size_t num_hdrbtns, btn_data_t* ftrbtns, const size_t num_ftrbtns)
{
    JADE_ASSERT(message);
    // Header and footer are optional

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = act->root_node;

    // Add a titlebar if deisred
    const bool have_hdr = title || num_hdrbtns;
    if (have_hdr) {
        parent = add_title_bar(act, title, hdrbtns, num_hdrbtns, NULL);
    }

    // Message - align center/middle if no carriage returns in message.
    // If multi-line, align top-left and let the caller manage the spacing.
    const bool msg_includes_crlf = strchr(message, '\n');
    gui_view_node_t* msgnode;
    gui_make_text(&msgnode, message, TFT_WHITE);
    if (!msg_includes_crlf) {
        gui_set_align(msgnode, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    } else {
        gui_set_align(msgnode, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    }

    // Apply any padding above the message (only applies if message contains cr/lf)
    if (msg_includes_crlf && toppad) {
        gui_set_padding(msgnode, GUI_MARGIN_ALL_DIFFERENT, toppad, 0, 0, 0);
    }

    if (!ftrbtns || !num_ftrbtns) {
        // Just a message, no buttons - just apply straight to the parent
        gui_set_parent(msgnode, parent);
    } else {
        // Relative height of buttons depends on whether there is a header
        gui_view_node_t* vsplit;
        const uint32_t btnheight = have_hdr ? 30 : 25;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 100 - btnheight, btnheight);
        gui_set_parent(vsplit, parent);

        // Add message to top of vsplit
        gui_set_parent(msgnode, vsplit);

        // Add buttons to below
        add_buttons(vsplit, UI_ROW, ftrbtns, num_ftrbtns);
    }

    return act;
}

// Activity to show a single value
gui_activity_t* make_show_single_value_activity(const char* name, const char* value, const bool show_helpbtn)
{
    JADE_ASSERT(name);
    JADE_ASSERT(value);

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    if (show_helpbtn) {
        hdrbtns[1].txt = "?";
        hdrbtns[1].ev_id = BTN_HELP;
    }

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, name, hdrbtns, 2, NULL);

    gui_view_node_t* node;
    gui_make_text_font(&node, value, TFT_WHITE, GUI_DEFAULT_FONT);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 24, 0, 0, 0);
    gui_set_parent(node, parent);

    return act;
}

// Make activity that displays a simple message - cannot be dismissed by caller
gui_activity_t* display_message_activity(const char* message)
{
    gui_activity_t* const act = make_show_message_activity(message, 0, NULL, NULL, 0, NULL, 0);
    gui_set_current_activity(act);
    return act;
}

gui_activity_t* display_processing_message_activity() { return display_message_activity("Processing..."); }

// Show passed dialog and handle events until a 'yes' or 'no', which is translated into a boolean return
// NOTE: only expect BTN_YES, BTN_NO and BTN_HELP events.
static bool await_yesno_activity_loop(gui_activity_t* const act, const char* help_url)
{
    JADE_ASSERT(act);
    // help_url is optional (but should be present if a BTN_HELP btn is present)

    int32_t ev_id;
    while (true) {
        gui_set_current_activity(act);

        // In a debug unattended ci build, assume 'Yes' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_YES;
#endif

        if (ret) {
            // Return true if 'Yes' was pressed, false if 'No'
            switch (ev_id) {
            case BTN_YES:
                return true;

            case BTN_NO:
                return false;

            case BTN_HELP:
                await_qr_help_activity(help_url);
                break;

            default:
                JADE_LOGW("Unexpected button event: %ld", ev_id);
                break;
            }
        }
    }
}

// Run activity that displays a message and awaits an 'ack' button click
void await_message_activity(const char* message)
{
    JADE_ASSERT(message);

    btn_data_t ftrbtn = { .txt = "Continue", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOP };

    gui_activity_t* const act = make_show_message_activity(message, 0, NULL, NULL, 0, &ftrbtn, 1);

    const bool rslt = await_yesno_activity_loop(act, NULL);
    JADE_ASSERT(rslt);
}

void await_error_activity(const char* errormessage) { await_message_activity(errormessage); }

// Generic activity that displays a message and Yes/No buttons, and waits
// for button press.  Function returns true if 'Yes' was pressed.
static bool await_yesno_activity_impl(const char* title, const char* message, const char* yes, const char* no,
    const bool default_selection, const char* help_url)
{
    // title is optional
    JADE_ASSERT(message);
    // help_url is optional - '?' button shown if passed

    btn_data_t hdrbtns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_HELP } };

    btn_data_t ftrbtns[] = { { .txt = no, .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO, .borders = GUI_BORDER_TOPRIGHT },
        { .txt = yes, .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOPLEFT } };

    gui_activity_t* const act = make_show_message_activity(message, 4, title, hdrbtns, help_url ? 2 : 0, ftrbtns, 2);
    gui_set_activity_initial_selection(act, ftrbtns[default_selection ? 1 : 0].btn);

    return await_yesno_activity_loop(act, help_url);
}

// Generic Yes/No activity
bool await_yesno_activity(const char* title, const char* message, const bool default_selection, const char* help_url)
{
    return await_yesno_activity_impl(title, message, "Yes", "No", default_selection, help_url);
}

// Variant of the Yes/No activity that is instead Skip/Yes
bool await_skipyes_activity(const char* title, const char* message, const bool default_selection, const char* help_url)
{
    return await_yesno_activity_impl(title, message, "Yes", "Skip", default_selection, help_url);
}

// Variant of the Yes/No activity that is instead Continue/Back (latter in title bar)
bool await_continueback_activity(
    const char* title, const char* message, const bool default_selection, const char* help_url)
{
    // title is optional
    JADE_ASSERT(message);
    // help_url is optional - '?' button shown if passed

    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_NO },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // Optionally add help btn
    if (help_url) {
        hdrbtns[1].txt = "?";
        hdrbtns[1].font = GUI_TITLE_FONT;
        hdrbtns[1].ev_id = BTN_HELP;
    }

    btn_data_t ftrbtn = { .txt = "Continue", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOP };

    gui_activity_t* const act = make_show_message_activity(message, 10, title, hdrbtns, 2, &ftrbtn, 1);
    gui_set_activity_initial_selection(act, (default_selection ? ftrbtn : hdrbtns[0]).btn);

    return await_yesno_activity_loop(act, help_url);
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
