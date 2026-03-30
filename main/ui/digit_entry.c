#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../random.h"
#include "../ui.h"

#define CHAR_BACKSPACE '|'
#define CHAR_ENTER '~'
static const char ENTRY_CHARS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', CHAR_BACKSPACE, CHAR_ENTER };
// The number of available digits, i.e. not including backspace or enter
#define NUM_ENTRY_DIGITS (sizeof(ENTRY_CHARS) / sizeof(ENTRY_CHARS[0]) - 2)

static inline bool entry_invert_navigation(void)
{
#if defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY) || defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3)
    // TTGO boards need to locally invert navigation so number entry matches the rest of the UI.
    return true;
#else
    return false;
#endif
}

static uint32_t get_max_digit_entry_char(const digit_entry_t* digit_entry)
{
    if (digit_entry->entry_type == DIGIT_ENTRY_INDEX) {
        return NUM_ENTRY_DIGITS + 2; // 0-9 + backspace + 'enter' to enter a short number
    }
    return NUM_ENTRY_DIGITS + 1; // 0-9 + backspace only since PIN entry requires all digits
}

static inline char get_current_digit_entry_char(const digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry->current_selected_value < get_max_digit_entry_char(digit_entry));
    return ENTRY_CHARS[digit_entry->current_selected_value];
}

static void reinitialise_current_entry_digit(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);

    switch (digit_entry->initial_state) {
    case ZERO:
        digit_entry->current_selected_value = 0;
        break;
    case POSITION:
        digit_entry->current_selected_value = digit_entry->selected_digit;
        break;
    default:
        digit_entry->current_selected_value = get_uniform_random_byte(NUM_ENTRY_DIGITS);
        break;
    }
}

static void update_digit_node(digit_entry_t* digit_entry, uint8_t i)
{
    JADE_ASSERT(digit_entry);
    JADE_ASSERT(i < DIGIT_ENTRY_SIZE);

    char strdigit[] = { '\0', '\0' };
    switch (digit_entry->digit_status[i]) {
    case EMPTY:
        gui_set_color(digit_entry->digit_nodes[i].fill_node, TFT_BLACK);
        gui_set_borders(digit_entry->digit_nodes[i].fill_node, TFT_LIGHTGREY, 2, GUI_BORDER_ALL);
        gui_update_text(digit_entry->digit_nodes[i].up_arrow_node, "");
        gui_update_text(digit_entry->digit_nodes[i].down_arrow_node, "");
        break;
    case SELECTED:
        gui_set_color(digit_entry->digit_nodes[i].fill_node, gui_get_highlight_color());
        gui_set_borders(digit_entry->digit_nodes[i].fill_node, gui_get_highlight_color(), 2, GUI_BORDER_ALL);
        gui_update_text(digit_entry->digit_nodes[i].up_arrow_node, "K");
        gui_update_text(digit_entry->digit_nodes[i].down_arrow_node, "L");
        strdigit[0] = ENTRY_CHARS[digit_entry->current_selected_value];
        break;
    case SET:
        gui_set_color(digit_entry->digit_nodes[i].fill_node, TFT_BLACK);
        gui_set_borders(digit_entry->digit_nodes[i].fill_node, gui_get_highlight_color(), 2, GUI_BORDER_ALL);
        gui_update_text(digit_entry->digit_nodes[i].up_arrow_node, "");
        gui_update_text(digit_entry->digit_nodes[i].down_arrow_node, "");
        strdigit[0] = digit_entry->digits_shown ? ENTRY_CHARS[digit_entry->digit[i]] : '*';
        break;
    }
    gui_update_text(digit_entry->digit_nodes[i].digit_node, strdigit);
    gui_repaint(digit_entry->digit_nodes[i].fill_node);
}

void make_digit_entry_activity(digit_entry_t* digit_entry, const char* title, const char* message)
{
    JADE_ASSERT(digit_entry);
    JADE_ASSERT(digit_entry->entry_type != DIGIT_ENTRY_INVALID);

    digit_entry->activity = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(digit_entry->activity, title, NULL, 0, &digit_entry->title);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    if (message) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_make_text(&node, message, TFT_WHITE);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    } else {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 10, 75, 15);
        gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, NULL);
    }
    gui_set_parent(vsplit, parent);
    gui_set_parent(node, vsplit);

    const size_t toppad = CONFIG_DISPLAY_HEIGHT > 200 ? 20 : CONFIG_DISPLAY_HEIGHT > 160 ? 12 : 4;
    const size_t lrpad = (CONFIG_DISPLAY_WIDTH - (6 * 35)) / 2;
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 6, 35, 35, 35, 35, 35, 35);
    gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, toppad, lrpad, toppad + 8, lrpad);
    gui_set_parent(hsplit, vsplit);

    reinitialise_current_entry_digit(digit_entry);

    for (size_t i = 0; i < DIGIT_ENTRY_SIZE; ++i) {
        digit_entry->digit[i] = 0xFF;
        digit_entry->digit_status[i] = i == 0 ? SELECTED : EMPTY;

        gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, hsplit);
        digit_entry->digit_nodes[i].fill_node = node;

        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 25, 50, 25);
        gui_set_parent(vsplit, node);
        // no need to store the vsplit

        // Up arrow
        gui_make_text_font(&node, "K", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, vsplit);
        digit_entry->digit_nodes[i].up_arrow_node = node;

        // Digit
        gui_make_text_font(&node, "", TFT_WHITE, DEJAVU24_FONT);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 5, 0, 0, 0);
        digit_entry->digit_nodes[i].digit_node = node;

        // Down arrow
        gui_make_text_font(&node, "L", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, vsplit);
        digit_entry->digit_nodes[i].down_arrow_node = node;

        update_digit_node(digit_entry, i);
    }
}

static bool next_selected_digit(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    JADE_ASSERT(digit_entry->selected_digit < DIGIT_ENTRY_SIZE);

    // make sure the '<' is not selected
    JADE_ASSERT(digit_entry->current_selected_value < 10);

    // copy the value
    digit_entry->digit[digit_entry->selected_digit] = digit_entry->current_selected_value;

    // set the status and update the ui
    digit_entry->digit_status[digit_entry->selected_digit] = SET;
    update_digit_node(digit_entry, digit_entry->selected_digit);
    ++digit_entry->selected_digit;

    // reached the last digit - cannot select next, return false
    if (digit_entry->selected_digit >= DIGIT_ENTRY_SIZE) {
        return false;
    }

    // set the status and update the ui
    digit_entry->digit_status[digit_entry->selected_digit] = SELECTED;

    reinitialise_current_entry_digit(digit_entry);
    update_digit_node(digit_entry, digit_entry->selected_digit);

    return true;
}

static bool prev_selected_digit(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    JADE_ASSERT(digit_entry->selected_digit < DIGIT_ENTRY_SIZE);

    // at the first digit - cannot select previous, return false
    if (digit_entry->selected_digit == 0) {
        return false;
    }

    // set the status and update the ui
    digit_entry->digit_status[digit_entry->selected_digit] = EMPTY;
    update_digit_node(digit_entry, digit_entry->selected_digit);

    --digit_entry->selected_digit;
    reinitialise_current_entry_digit(digit_entry);

    // set the status and update the ui
    digit_entry->digit_status[digit_entry->selected_digit] = SELECTED;
    update_digit_node(digit_entry, digit_entry->selected_digit);

    return true;
}

// Returns true if number entry completes and digit_entry->digit is valid,
// and false if number entry abandoned and digit_entry->digit is not to be used.
bool run_digit_entry_loop(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    JADE_ASSERT(digit_entry->activity);

    int32_t ev_id;
    while (true) {
        // wait for a GUI event
        gui_activity_wait_event(digit_entry->activity, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
        if (entry_invert_navigation()) {
            // Swap left/right wheel events
            if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                ev_id = GUI_WHEEL_RIGHT_EVENT;
            } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                ev_id = GUI_WHEEL_LEFT_EVENT;
            }
        }

        switch (ev_id) {
        case GUI_WHEEL_LEFT_EVENT:
            digit_entry->current_selected_value
                = (digit_entry->current_selected_value + get_max_digit_entry_char(digit_entry) - 1)
                % get_max_digit_entry_char(digit_entry);
            update_digit_node(digit_entry, digit_entry->selected_digit);
            break;
        case GUI_WHEEL_RIGHT_EVENT:
            digit_entry->current_selected_value
                = (digit_entry->current_selected_value + 1) % get_max_digit_entry_char(digit_entry);
            update_digit_node(digit_entry, digit_entry->selected_digit);
            break;

        default:
            if (ev_id == gui_get_click_event()) {
                switch (get_current_digit_entry_char(digit_entry)) {
                case CHAR_BACKSPACE:
                    if (!prev_selected_digit(digit_entry)) {
                        // Returns false when click 'backspace' on first digit (cannot move to previous)
                        return false; // number entry abandoned
                    }
                    break;
                case CHAR_ENTER:
                    // only valid for digit_entry_type == DIGIT_ENTRY_INDEX
                    JADE_ASSERT(digit_entry->entry_type == DIGIT_ENTRY_INDEX);
                    // If enter clicked on first digit, abandon entry
                    if (digit_entry->selected_digit == 0) {
                        return false; // number entry abandoned
                    }
                    return true; // number entry complete
                default:
                    if (!next_selected_digit(digit_entry)) {
                        // Returns false when click number on last digit (cannot move to next)
                        return true; // number entry complete
                    }
                    break;
                }
            }
        }
    }
}

void reset_digit_entry(digit_entry_t* digit_entry, const char* title)
{
    JADE_ASSERT(digit_entry);
    // title is optional

    // Select and re-randomise first digit
    digit_entry->selected_digit = 0;
    reinitialise_current_entry_digit(digit_entry);

    // Mark all digits as unset
    for (size_t i = 0; i < DIGIT_ENTRY_SIZE; ++i) {
        digit_entry->digit[i] = 0xFF;
        digit_entry->digit_status[i] = i == 0 ? SELECTED : EMPTY;
        update_digit_node(digit_entry, i);
    }

    // Update title if passed
    if (title) {
        gui_update_text(digit_entry->title, title);
    }
}

uint32_t get_entry_as_number(const digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    if (digit_entry->entry_type == DIGIT_ENTRY_INDEX) {
        JADE_ASSERT(digit_entry->selected_digit > 0 && digit_entry->selected_digit <= DIGIT_ENTRY_SIZE); // entry valid
    } else {
        JADE_ASSERT(digit_entry->selected_digit == DIGIT_ENTRY_SIZE); // entry complete
    }

    uint32_t val = 0;
    for (uint8_t i = 0; i < digit_entry->selected_digit; ++i) {
        JADE_ASSERT(digit_entry->digit_status[i] == SET);
        JADE_ASSERT(digit_entry->digit[i] < NUM_ENTRY_DIGITS);
        val = val * 10 + digit_entry->digit[i];
    }

    return val;
}
#endif // AMALGAMATED_BUILD
