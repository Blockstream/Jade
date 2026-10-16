#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../random.h"
#include "../ui.h"

#define CHAR_BACKSPACE '|'
#define CHAR_ENTER '~'
static const char ENTRY_CHARS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', CHAR_BACKSPACE, CHAR_ENTER };
enum {
    NUM_ENTRY_CHARS = sizeof(ENTRY_CHARS) / sizeof(ENTRY_CHARS[0]),
    // The number of available digits, i.e. not including backspace or enter
    NUM_ENTRY_DIGITS = NUM_ENTRY_CHARS - 2,
};

static inline bool entry_invert_navigation(void)
{
#if defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY) || defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3)                             \
    || defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS_2)
    // These boards need to locally invert navigation so number entry matches the rest of the UI.
    return true;
#else
    return false;
#endif
}

#ifdef CONFIG_DISPLAY_TOUCH_DIRECT
// With direct touch, pin entry uses a keypad rather than the digit carousel
static inline bool uses_keypad(const digit_entry_t* digit_entry) { return digit_entry->entry_type == DIGIT_ENTRY_PIN; }
#endif

static uint8_t get_digit_entry_size(const digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    const uint8_t max_digits = digit_entry->max_digits ? digit_entry->max_digits : DIGIT_ENTRY_SIZE;
    // TODO: Relax this assertion once we support an arbitrary number of digits up to DIGIT_ENTRY_SIZE
    JADE_ASSERT(max_digits == DIGIT_ENTRY_WORD_NUMBER_SIZE || max_digits == DIGIT_ENTRY_SIZE);
    return max_digits;
}

static bool digit_entry_allows_enter(const digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    return digit_entry->entry_type == DIGIT_ENTRY_INDEX || digit_entry->entry_type == DIGIT_ENTRY_WORD_NUMBER;
}

static uint32_t get_candidate_entry_value(const digit_entry_t* digit_entry, const uint8_t value)
{
    JADE_ASSERT(digit_entry && value < NUM_ENTRY_DIGITS);

    uint32_t candidate = 0;
    for (uint8_t i = 0; i < digit_entry->selected_digit; ++i) {
        JADE_ASSERT(digit_entry->digit_status[i] == SET && digit_entry->digit[i] < NUM_ENTRY_DIGITS);
        candidate = candidate * 10 + digit_entry->digit[i];
    }
    return candidate * 10 + value;
}

static bool digit_entry_digit_allowed(const digit_entry_t* digit_entry, const uint8_t value)
{
    JADE_ASSERT(digit_entry && value < NUM_ENTRY_DIGITS);

    const uint8_t entry_size = get_digit_entry_size(digit_entry);
    JADE_ASSERT(digit_entry->selected_digit < entry_size);

    if (!digit_entry->max_value) {
        return true;
    }

    return get_candidate_entry_value(digit_entry, value) <= digit_entry->max_value;
}

static bool digit_entry_value_allowed(const digit_entry_t* digit_entry, const uint8_t value)
{
    JADE_ASSERT(digit_entry && value < NUM_ENTRY_CHARS);

    if (value < NUM_ENTRY_DIGITS) {
        return digit_entry_digit_allowed(digit_entry, value);
    }
    if (ENTRY_CHARS[value] == CHAR_BACKSPACE) {
        return true;
    }
    if (digit_entry_allows_enter(digit_entry)) {
        return ENTRY_CHARS[value] == CHAR_ENTER;
    }
    return false;
}

static void normalise_current_digit_entry_value(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    if (digit_entry_value_allowed(digit_entry, digit_entry->current_selected_value)) {
        return;
    }

    if (digit_entry_allows_enter(digit_entry) && digit_entry->selected_digit > 0) {
        digit_entry->current_selected_value = NUM_ENTRY_CHARS - 1;
        JADE_ASSERT(ENTRY_CHARS[digit_entry->current_selected_value] == CHAR_ENTER
            && digit_entry_value_allowed(digit_entry, digit_entry->current_selected_value));
        return;
    }

    for (uint8_t i = 0; i < NUM_ENTRY_CHARS; ++i) {
        digit_entry->current_selected_value = i;
        if (digit_entry_value_allowed(digit_entry, digit_entry->current_selected_value)) {
            return;
        }
    }

    JADE_ASSERT(false);
}

static void step_current_digit_entry_value(digit_entry_t* digit_entry, const int8_t direction)
{
    JADE_ASSERT(digit_entry && (direction == -1 || direction == 1));

    for (uint8_t i = 0; i < NUM_ENTRY_CHARS; ++i) {
        digit_entry->current_selected_value
            = (digit_entry->current_selected_value + NUM_ENTRY_CHARS + direction) % NUM_ENTRY_CHARS;
        if (digit_entry_value_allowed(digit_entry, digit_entry->current_selected_value)) {
            return;
        }
    }
    JADE_ASSERT(false);
}

static inline char get_current_digit_entry_char(const digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry_value_allowed(digit_entry, digit_entry->current_selected_value));
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
    normalise_current_digit_entry_value(digit_entry);
}

static void update_digit_node(digit_entry_t* digit_entry, uint8_t i)
{
    JADE_ASSERT(digit_entry && i < get_digit_entry_size(digit_entry));

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
#ifdef CONFIG_DISPLAY_TOUCH_DIRECT
        if (uses_keypad(digit_entry)) {
            // No arrows or preselected digit - the value comes from the keypad
            gui_update_text(digit_entry->digit_nodes[i].up_arrow_node, "");
            gui_update_text(digit_entry->digit_nodes[i].down_arrow_node, "");
            break;
        }
#endif
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

// Make the row of digit boxes common to the carousel and keypad activities
static void make_digit_entry_boxes(
    digit_entry_t* digit_entry, gui_view_node_t* parent, const size_t toppad, const size_t botpad)
{
    const uint8_t entry_size = get_digit_entry_size(digit_entry);
    const size_t lrpad = (CONFIG_DISPLAY_WIDTH - (entry_size * 35)) / 2;
    gui_view_node_t* hsplit;
    // TODO: Add splits for other entry widths once they get support
    if (entry_size == DIGIT_ENTRY_WORD_NUMBER_SIZE) {
        gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 4, 35, 35, 35, 35);
    } else {
        JADE_ASSERT(entry_size == DIGIT_ENTRY_SIZE);
        gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 6, 35, 35, 35, 35, 35, 35);
    }
    gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, toppad, lrpad, botpad, lrpad);
    gui_set_parent(hsplit, parent);

    reinitialise_current_entry_digit(digit_entry);

    gui_view_node_t* node;
    gui_view_node_t* vsplit;
    for (size_t i = 0; i < entry_size; ++i) {
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

#ifdef CONFIG_DISPLAY_TOUCH_DIRECT
// Tappable pin entry keypad, used instead of the digit carousel
// The title bar 'back' button acts as backspace
static void make_pin_keypad_activity(digit_entry_t* digit_entry, const char* title, const char* message)
{
    digit_entry->activity = gui_make_activity();
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_KEYBOARD_BACKSPACE },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };
    gui_view_node_t* const parent = add_title_bar(digit_entry->activity, title, hdrbtns, 2, &digit_entry->title);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 14, 32, 27, 27);
    gui_set_parent(vsplit, parent);

    if (message) {
        gui_make_text(&node, message, TFT_WHITE);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    } else {
        gui_make_fill(&node, TFT_BLACK, FILL_PLAIN, NULL);
    }
    gui_set_parent(node, vsplit);

    make_digit_entry_boxes(digit_entry, vsplit, 2, 2);

    // Put the digits in random positions, so where the taps land does not give
    // away the pin (as the random starting value does for the digit carousel)
    char keys[NUM_ENTRY_DIGITS];
    for (size_t i = 0; i < NUM_ENTRY_DIGITS; ++i) {
        keys[i] = ENTRY_CHARS[i];
    }
    for (size_t i = NUM_ENTRY_DIGITS - 1; i > 0; --i) {
        const uint8_t j = get_uniform_random_byte(i + 1);
        const char tmp = keys[i];
        keys[i] = keys[j];
        keys[j] = tmp;
    }

    // Two rows of five large digit keys
    for (size_t r = 0; r < 2; ++r) {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 5, 20, 20, 20, 20, 20);
        gui_set_parent(hsplit, vsplit);

        for (size_t c = 0; c < 5; ++c) {
            const char key = keys[r * 5 + c];
            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, gui_get_highlight_color(), BTN_KEYBOARD_ASCII_OFFSET + key, NULL);
            gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn, TFT_BLUE, 1, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, gui_get_highlight_color());
            gui_set_parent(btn, hsplit);

            const char str[] = { key, '\0' };
            gui_view_node_t* label;
            gui_make_text_font(&label, str, TFT_WHITE, DEJAVU24_FONT);
            gui_set_parent(label, btn);
            gui_set_align(label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }
    }
}
#endif // CONFIG_DISPLAY_TOUCH_DIRECT

void make_digit_entry_activity(digit_entry_t* digit_entry, const char* title, const char* message)
{
    JADE_ASSERT(digit_entry && digit_entry->entry_type != DIGIT_ENTRY_INVALID);

#ifdef CONFIG_DISPLAY_TOUCH_DIRECT
    if (uses_keypad(digit_entry)) {
        make_pin_keypad_activity(digit_entry, title, message);
        return;
    }
#endif

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
    make_digit_entry_boxes(digit_entry, vsplit, toppad, toppad + 8);
}

static bool next_selected_digit(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry);
    const uint8_t entry_size = get_digit_entry_size(digit_entry);
    JADE_ASSERT(digit_entry->selected_digit < entry_size);

    // make sure the '<' is not selected
    JADE_ASSERT(digit_entry->current_selected_value < 10);

    // copy the value
    digit_entry->digit[digit_entry->selected_digit] = digit_entry->current_selected_value;

    // set the status and update the ui
    digit_entry->digit_status[digit_entry->selected_digit] = SET;
    update_digit_node(digit_entry, digit_entry->selected_digit);
    ++digit_entry->selected_digit;

    // reached the last digit - cannot select next, return false
    if (digit_entry->selected_digit >= entry_size) {
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
    JADE_ASSERT(digit_entry && digit_entry->selected_digit < get_digit_entry_size(digit_entry));

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

#ifdef CONFIG_DISPLAY_TOUCH_DIRECT
// As run_digit_entry_loop() below, but driven by the keypad buttons
static bool run_pin_keypad_loop(digit_entry_t* digit_entry)
{
    int32_t ev_id;
    while (true) {
        gui_activity_wait_event(digit_entry->activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        if (ev_id == BTN_KEYBOARD_BACKSPACE) {
            if (!prev_selected_digit(digit_entry)) {
                // 'backspace' on first digit (cannot move to previous)
                return false; // number entry abandoned
            }
        } else if (ev_id >= BTN_KEYBOARD_ASCII_OFFSET + '0' && ev_id <= BTN_KEYBOARD_ASCII_OFFSET + '9') {
            digit_entry->current_selected_value = ev_id - BTN_KEYBOARD_ASCII_OFFSET - '0';
            if (!next_selected_digit(digit_entry)) {
                // Number entered on last digit (cannot move to next)
                return true; // number entry complete
            }
        }
    }
}
#endif // CONFIG_DISPLAY_TOUCH_DIRECT

// Returns true if number entry completes and digit_entry->digit is valid,
// and false if number entry abandoned and digit_entry->digit is not to be used.
bool run_digit_entry_loop(digit_entry_t* digit_entry)
{
    JADE_ASSERT(digit_entry && digit_entry->activity);

#ifdef CONFIG_DISPLAY_TOUCH_DIRECT
    if (uses_keypad(digit_entry)) {
        return run_pin_keypad_loop(digit_entry);
    }
#endif

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
            step_current_digit_entry_value(digit_entry, -1);
            update_digit_node(digit_entry, digit_entry->selected_digit);
            break;
        case GUI_WHEEL_RIGHT_EVENT:
            step_current_digit_entry_value(digit_entry, 1);
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
                    JADE_ASSERT(digit_entry_allows_enter(digit_entry));
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
    for (size_t i = 0; i < get_digit_entry_size(digit_entry); ++i) {
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
    if (digit_entry_allows_enter(digit_entry)) {
        JADE_ASSERT(
            digit_entry->selected_digit > 0 && digit_entry->selected_digit <= get_digit_entry_size(digit_entry));
    } else {
        JADE_ASSERT(digit_entry->selected_digit == get_digit_entry_size(digit_entry)); // entry complete
    }

    uint32_t val = 0;
    for (uint8_t i = 0; i < digit_entry->selected_digit; ++i) {
        JADE_ASSERT(digit_entry->digit_status[i] == SET && digit_entry->digit[i] < NUM_ENTRY_DIGITS);
        val = val * 10 + digit_entry->digit[i];
    }

    return val;
}
#endif // AMALGAMATED_BUILD
