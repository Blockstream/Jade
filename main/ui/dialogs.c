#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

void await_qr_help_activity(const char* url);

// releative
#define TITLE_BAR_HEIGHT_PCNT 20
#define FOOTER_BUTTONS_HEIGHT_PCNT 25

// absolute, appropriate for font being used and adjusted slightly for larger screens
#define MESSAGE_LINE_ROW_HEIGHT (CONFIG_DISPLAY_HEIGHT >= 150 ? 22 : 20)

// Helper to update dynamic menu item label (name: value)
void update_menu_item(gui_view_node_t* node, const char* label, const char* value)
{
    char buf[32];
    const int ret = snprintf(buf, sizeof(buf), "%s: %s", label, value);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    gui_update_text(node, buf);
}

// Handles up to 7 splits, row or column.
// layout == UI_ROW -> [ x | y | z ] items in a row -> an hsplit
// layout == UI_COLUMN -> [ x / y / z ] items in a column -> a vsplit
gui_view_node_t* make_even_split(const ui_button_layout_t layout, const uint8_t num_splits)
{
    JADE_ASSERT(layout == UI_ROW || layout == UI_COLUMN);
    // num_splits range asserted in switch below

    // Make the split relevant for the number of buttons
    typedef void (*make_split_fn)(gui_view_node_t * *ptr, enum gui_split_type kind, uint8_t parts, ...);
    make_split_fn make_split = (layout == UI_COLUMN) ? gui_make_vsplit : gui_make_hsplit;

    // Make a split for the number of buttons (if greater than one)
    gui_view_node_t* split = NULL;
    switch (num_splits) {
    case 2:
        make_split(&split, GUI_SPLIT_RELATIVE, 2, 50, 50);
        break;
    case 3:
        make_split(&split, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
        break;
    case 4:
        make_split(&split, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
        break;
    case 5:
        make_split(&split, GUI_SPLIT_RELATIVE, 5, 20, 20, 20, 20, 20);
        break;
    case 6:
        make_split(&split, GUI_SPLIT_RELATIVE, 6, 17, 16, 17, 17, 16, 17);
        break;
    case 7:
        make_split(&split, GUI_SPLIT_RELATIVE, 7, 14, 15, 14, 14, 14, 15, 14);
        break;
    default:
        JADE_ASSERT_MSG(false, "Unsupported split size");
    }
    return split;
}

// Helper to make a standard button, for consistent look and feel behaviour
void add_button(gui_view_node_t* parent, btn_data_t* btn_info)
{
    JADE_ASSERT(btn_info);

    // Cannot specify both 'text label' and 'explicit content'
    JADE_ASSERT(!btn_info->txt || !btn_info->content);

    gui_view_node_t* btn;

    // No event implies no 'pressable' button in this position - use an empty 'vsplit' as a spacer
    if (btn_info->ev_id == GUI_BUTTON_EVENT_NONE) {
        gui_make_vsplit(&btn, GUI_SPLIT_RELATIVE, 1, 100); // no-op spacer
    } else {
        gui_make_button(&btn, TFT_BLACK, gui_get_highlight_color(), btn_info->ev_id, NULL);
    }
    gui_set_parent(btn, parent);

    // If borders explcitly specified, show in dark grey
    // 0 implies default behaviour - no visible borders when not selected
    if (btn_info->borders) {
        gui_set_borders(btn, GUI_BLOCKSTREAM_BUTTONBORDER_GREY, 1, btn_info->borders);
    } else {
        gui_set_borders(btn, TFT_BLACK, 1, GUI_BORDER_ALL);
    }

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

// Helper to create buttons in a row or column
void add_buttons(gui_view_node_t* parent, const ui_button_layout_t layout, btn_data_t* btns, const size_t num_btns)
{
    JADE_ASSERT(layout == UI_ROW || layout == UI_COLUMN);
    JADE_ASSERT(btns);
    JADE_ASSERT(num_btns);

    if (num_btns == 1) {
        // skip intermediate split, apply button directly to parent
        // ('layout' (row or column) is irrelevant in this case)
        add_button(parent, btns);
        return;
    }

    // Make a split for the number of buttons (if greater than one)
    gui_view_node_t* const split = make_even_split(layout, num_btns);
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
            gui_make_fill(&titlenode, TFT_BLACK, FILL_PLAIN, NULL);
            gui_set_parent(*title_node, titlenode);
        }
    } else {
        // No title, just a blank space
        gui_make_fill(&titlenode, TFT_BLACK, FILL_PLAIN, NULL);
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
    JADE_ASSERT(btns || !num_btns);

    // Split off the top 20% as the title bar
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, TITLE_BAR_HEIGHT_PCNT, 100 - TITLE_BAR_HEIGHT_PCNT);
    gui_set_parent(vsplit, activity->root_node);

    // Populate the title bar
    populate_title_bar(vsplit, title, btns, num_btns, title_node);

    // Return the new parent for further ui elements
    return vsplit;
}

// Helper to create an activity which is a grid of (up to 7x7) text items
// NOTE: the text is passed as one char large array containing embedded terminators
// to delineate the separate texts - eg: ... , "abc\0def\0ghi\0j\0", 4)
gui_activity_t* make_text_grid_activity(const char* title, btn_data_t* hdrbtns, const size_t num_hdrbtns,
    const size_t toppad, const uint8_t xcells, const uint8_t ycells, const char* texts, const size_t num_texts,
    const uint32_t font, const char** remaining_texts)
{
    // Title and header are optional
    JADE_ASSERT(hdrbtns || !num_hdrbtns);
    JADE_ASSERT(xcells);
    JADE_ASSERT(ycells);
    JADE_ASSERT(texts);
    JADE_ASSERT(num_texts);
    JADE_ASSERT(num_texts <= xcells * ycells);
    // remaining_texts pointer is optional

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = act->root_node;

    // Add a titlebar if deisred
    const bool have_hdr = title || num_hdrbtns;
    if (have_hdr) {
        parent = add_title_bar(act, title, hdrbtns, num_hdrbtns, NULL);
    }

    // Make grid - reads across then down
    gui_view_node_t* const vsplit = make_even_split(UI_COLUMN, ycells);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, toppad, 2, 0, 2);
    gui_set_parent(vsplit, parent);

    const char* text_item = texts;
    for (uint8_t y = 0; y < ycells; ++y) {
        gui_view_node_t* hsplit = make_even_split(UI_ROW, xcells);
        gui_set_parent(hsplit, vsplit);

        for (uint8_t x = 0; x < xcells; ++x) {
            const int itxt = (y * xcells) + x;
            if (itxt < num_texts) {
                gui_view_node_t* node;
                gui_make_text_font(&node, text_item, TFT_WHITE, font);
                gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
                gui_set_parent(node, hsplit);
                text_item += strlen(text_item) + 1;
            }
        }
    }

    // Return pointer indicating where we have read/displayed up to
    // NOTE: could be off the end of the 'texts' string if entire string consumed.
    if (remaining_texts) {
        *remaining_texts = text_item;
    }

    return act;
}

// Helper to create an activity to show a vertical menu
// Must pass title-bar information - supports up to 4 menu buttons
gui_activity_t* make_menu_activity(
    const char* title, btn_data_t* hdrbtns, const size_t num_hdrbtns, btn_data_t* menubtns, const size_t num_menubtns)
{
    JADE_ASSERT(title);
    // Header buttons are optional
    JADE_ASSERT(menubtns);
    JADE_ASSERT(num_menubtns);
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
    if (num_menubtns < 3) {
        gui_view_node_t* vsplit;
        const uint32_t split = num_menubtns == 2 ? 65 : 35;
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, split, 100 - split);
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
gui_activity_t* make_show_message_activity(const char* message[], const size_t message_size, const char* title,
    btn_data_t* hdrbtns, const size_t num_hdrbtns, btn_data_t* ftrbtns, const size_t num_ftrbtns)
{
    JADE_ASSERT(message);
    JADE_ASSERT(message_size);
    JADE_ASSERT(message_size < 5);
    // Header and footer are optional
    JADE_ASSERT(hdrbtns || !num_hdrbtns);
    JADE_ASSERT(ftrbtns || !num_ftrbtns);

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = act->root_node;

    // Add a titlebar if deisred
    const bool have_hdr = title || num_hdrbtns;
    if (have_hdr) {
        parent = add_title_bar(act, title, hdrbtns, num_hdrbtns, NULL);
    }

    // Message - align center/middle if no carriage returns in message.
    // If multi-line, align top-left and let the caller manage the spacing.
    gui_view_node_t* msgnode;
    size_t toppad = 0;
    if (message_size > 1) {
        // Create a vsplit for the text lines
        const size_t ypct
            = 100 - (have_hdr ? TITLE_BAR_HEIGHT_PCNT : 0) - (num_ftrbtns ? FOOTER_BUTTONS_HEIGHT_PCNT : 0);
        JADE_ASSERT(ypct > 50 && ypct <= 100); // sanity cehck
        const size_t yextent = (ypct * CONFIG_DISPLAY_HEIGHT) / 100;

        const size_t h = MESSAGE_LINE_ROW_HEIGHT; // each text line height, appropriate for the default font height
        const size_t msgextent = message_size * h;
        toppad = msgextent < yextent ? (yextent - msgextent) / 2 : 0; // top padding to centre message
        JADE_LOGD("ypct, yextent, msgextent, toppad: %u, %u, %u, %u", ypct, yextent, msgextent, toppad);
        JADE_ASSERT(toppad < 100); // sanity check

        switch (message_size) {
        case 2:
            gui_make_vsplit(&msgnode, GUI_SPLIT_ABSOLUTE, 2, h, h);
            break;
        case 3:
            gui_make_vsplit(&msgnode, GUI_SPLIT_ABSOLUTE, 3, h, h, h);
            break;
        case 4:
            gui_make_vsplit(&msgnode, GUI_SPLIT_ABSOLUTE, 4, h, h, h, h);
            break;
        default:
            JADE_ASSERT_MSG(false, "Unsupported number of text lines");
        }

        // Create text lines, each one horizontally centered
        for (size_t i = 0; i < message_size; ++i) {
            if (strchr(message[i], '\n')) {
                JADE_LOGW("Multiline message includes explicit \n!!");
            }
            gui_view_node_t* linenode;
            gui_make_text(&linenode, message[i], TFT_WHITE);
            gui_set_align(linenode, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
            gui_set_parent(linenode, msgnode);
        }
    } else {
        // Just create a single text node
        gui_make_text(&msgnode, message[0], TFT_WHITE);

        // Align center/middle if no carriage returns in message, otherwise
        // align top-left and let the caller manage the spacing.
        if (strchr(message[0], '\n')) {
            gui_set_align(msgnode, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
        } else {
            gui_set_align(msgnode, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }
    }

    // Apply any padding above the message, and a small offset from the screen edges
    gui_set_padding(msgnode, GUI_MARGIN_ALL_DIFFERENT, toppad, 2, 0, 2);

    if (!num_ftrbtns) {
        // Just a message, no buttons - just apply straight to the parent
        gui_set_parent(msgnode, parent);
    } else {
        // Relative height of buttons depends on whether there is a header
        gui_view_node_t* vsplit;
        const uint32_t btnheight = (100 * FOOTER_BUTTONS_HEIGHT_PCNT) / (100 - (have_hdr ? TITLE_BAR_HEIGHT_PCNT : 0));
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
gui_activity_t* display_message_activity(const char* message[], const size_t message_size)
{
    gui_activity_t* const act = make_show_message_activity(message, message_size, NULL, NULL, 0, NULL, 0);
    gui_set_current_activity(act);
    return act;
}

gui_activity_t* display_processing_message_activity()
{
    const char* message[] = { "Processing..." };
    return display_message_activity(message, 1);
}

// Show passed dialog and handle events until a 'yes' or 'no', which is translated into a boolean return
// NOTE: only expect BTN_YES, BTN_NO and BTN_HELP events.
static bool await_yesno_activity_loop(gui_activity_t* const act, const char* help_url)
{
    JADE_ASSERT(act);
    // help_url is optional (but should be present if a BTN_HELP btn is present)

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_YES);
        // Return true if 'Yes' was pressed, false if 'No'
        switch (ev_id) {
        case BTN_YES:
            return true;

        case BTN_NO:
            return false;

        case BTN_HELP:
            await_qr_help_activity(help_url);
            break;

        case BTN_EVENT_TIMEOUT:
            break;

        default:
            JADE_LOGW("Unexpected button event: %ld", ev_id);
            break;
        }
    }
}

// Run activity that displays a message and awaits an 'ack' button click
void await_message_activity(const char* message[], const size_t message_size)
{
    btn_data_t ftrbtn = { .txt = "Continue", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOP };

    gui_activity_t* const act = make_show_message_activity(message, message_size, NULL, NULL, 0, &ftrbtn, 1);

    const bool rslt = await_yesno_activity_loop(act, NULL);
    JADE_ASSERT(rslt);
}

void await_error_activity(const char* message[], const size_t message_size)
{
    await_message_activity(message, message_size);
}

// Generic activity that displays a message and Yes/No buttons, and waits
// for button press.  Function returns true if 'Yes' was pressed.
static bool await_yesno_activity_impl(const char* title, const char* message[], const size_t message_size,
    const char* yes, const char* no, const bool default_selection, const char* help_url)
{
    // title is optional
    JADE_ASSERT(message);
    JADE_ASSERT(message_size);
    JADE_ASSERT(yes);
    JADE_ASSERT(no);
    // help_url is optional - '?' button shown if passed

    btn_data_t hdrbtns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_HELP } };

    btn_data_t ftrbtns[] = { { .txt = no, .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO, .borders = GUI_BORDER_TOPRIGHT },
        { .txt = yes, .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOPLEFT } };

    gui_activity_t* const act
        = make_show_message_activity(message, message_size, title, hdrbtns, help_url ? 2 : 0, ftrbtns, 2);
    gui_set_activity_initial_selection(ftrbtns[default_selection ? 1 : 0].btn);

    return await_yesno_activity_loop(act, help_url);
}

// Generic Yes/No activity
bool await_yesno_activity(const char* title, const char* message[], const size_t message_size,
    const bool default_selection, const char* help_url)
{
    return await_yesno_activity_impl(title, message, message_size, "Yes", "No", default_selection, help_url);
}

// Variant of the Yes/No activity that is instead Skip/Yes
bool await_skipyes_activity(const char* title, const char* message[], const size_t message_size,
    const bool default_selection, const char* help_url)
{
    return await_yesno_activity_impl(title, message, message_size, "Yes", "Skip", default_selection, help_url);
}

// Variant of the Yes/No activity that is instead Continue/Back (latter in title bar)
bool await_continueback_activity(const char* title, const char* message[], const size_t message_size,
    const bool default_selection, const char* help_url)
{
    // title is optional
    JADE_ASSERT(message);
    JADE_ASSERT(message_size);
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

    gui_activity_t* const act = make_show_message_activity(message, message_size, title, hdrbtns, 2, &ftrbtn, 1);
    gui_set_activity_initial_selection((default_selection ? ftrbtn : hdrbtns[0]).btn);

    return await_yesno_activity_loop(act, help_url);
}

// Updatable label with left/right arrows
gui_activity_t* make_carousel_activity(const char* title, gui_view_node_t** label, gui_view_node_t** item)
{
    JADE_ASSERT(title);
    // label is optional
    JADE_INIT_OUT_PPTR(item);

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(act, title, NULL, 0, NULL);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    if (label) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 40, 35, 25);
        gui_set_parent(vsplit, parent);

        // Updateable label
        gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, vsplit);

        gui_make_text(label, "", TFT_WHITE);
        gui_set_padding(*label, GUI_MARGIN_ALL_DIFFERENT, 0, 8, 0, 0);
        gui_set_align(*label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(*label, node);
    } else {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 25, 35, 40);
        gui_set_parent(vsplit, parent);

        gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, vsplit);
    }

    // Background fill
    gui_make_fill(&node, gui_get_highlight_color(), FILL_HIGHLIGHT, vsplit);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 10, 80, 10);
    gui_set_parent(hsplit, node);

    // Left arrow
    gui_make_text_font(&node, "H", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // Updateable carousel item
    gui_make_fill(&node, gui_get_highlight_color(), FILL_HIGHLIGHT, hsplit);

    gui_make_text(item, "", TFT_WHITE);
    gui_set_align(*item, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*item, node);

    // Right arrow
    gui_make_text_font(&node, "I", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    return act;
}

// Function to update the highlight colour used for the selection
void update_carousel_highlight_color(const gui_view_node_t* text_label, const color_t color, const bool repaint)
{
    // Assert is label in carousel as created above
    JADE_ASSERT(text_label);
    JADE_ASSERT(text_label->kind == TEXT);
    JADE_ASSERT(text_label->parent);
    JADE_ASSERT(text_label->parent->kind == FILL);
    JADE_ASSERT(text_label->parent->parent);
    JADE_ASSERT(text_label->parent->parent->kind == HSPLIT);
    JADE_ASSERT(text_label->parent->parent->parent);
    JADE_ASSERT(text_label->parent->parent->parent->kind == FILL);

    // Update the selection colour of the two fill elements
    gui_set_color(text_label->parent, color);
    gui_set_color(text_label->parent->parent->parent, color);

    // Repaint if requested
    if (repaint) {
        gui_repaint(text_label->parent->parent->parent);
    }
}

// The progress-bar structure indicated is populated, and should be used to update the progress
// using the update_progress_bar() function below.
void make_progress_bar(gui_view_node_t* parent, progress_bar_t* progress_bar)
{
    JADE_ASSERT(parent);
    JADE_ASSERT(progress_bar);

    // A progress-bar can be transparent, but should the value decrease the parent would
    // need to be redrawn to reduce the amount of 'fill' in the bar.
    if (progress_bar->transparent) {
        gui_make_vsplit(&progress_bar->container, GUI_SPLIT_RELATIVE, 1, 100);
        gui_make_vsplit(&progress_bar->progress_bar, GUI_SPLIT_RELATIVE, 1, 100);
    } else {
        gui_make_fill(&progress_bar->container, TFT_BLACK, FILL_PLAIN, NULL);
        gui_make_fill(&progress_bar->progress_bar, TFT_BLACK, FILL_PLAIN, NULL);
    }

    gui_set_borders(progress_bar->container, TFT_WHITE, 2, GUI_BORDER_ALL);
    gui_set_margins(progress_bar->container, GUI_MARGIN_TWO_VALUES, 4, 16);
    gui_set_parent(progress_bar->container, parent);

    gui_set_margins(progress_bar->progress_bar, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(progress_bar->progress_bar, gui_get_highlight_color(), 0, GUI_BORDER_LEFT);
    gui_set_parent(progress_bar->progress_bar, progress_bar->container);
}

// Create a progress bar screen, with the given title.
// The progress-bar structure indicated is populated, and should be used to update the progress
// using the update_progress_bar() function below.
gui_activity_t* make_progress_bar_activity(const char* title, const char* message, progress_bar_t* progress_bar)
{
    JADE_ASSERT(title);
    JADE_ASSERT(message);
    JADE_ASSERT(progress_bar);

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(act, title, NULL, 0, NULL);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 25, 45, 30);
    gui_set_parent(vsplit, parent);

    // First row, message text
    gui_make_text(&node, message, TFT_WHITE);
    gui_set_parent(node, vsplit);
    gui_set_padding(node, GUI_MARGIN_TWO_VALUES, 0, 12);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // second row, progress bar
    make_progress_bar(vsplit, progress_bar);

    // third row, percentage text
    gui_make_text(&node, "0%", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    progress_bar->pcnt_txt = node;

    gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, vsplit);

    gui_set_parent(progress_bar->pcnt_txt, node);

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

        gui_set_borders(progress_bar->progress_bar, gui_get_highlight_color(), width_shaded, GUI_BORDER_LEFT);
        gui_repaint(progress_bar->progress_bar);
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
#endif // AMALGAMATED_BUILD
