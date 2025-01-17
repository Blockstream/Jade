#include "../button_events.h"
#include "../jade_assert.h"
#include "../random.h"
#include "../ui.h"

#include <math.h>

static const char CHAR_BACKSPACE = '|';
static const char PIN_CHARS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', CHAR_BACKSPACE };
static const uint32_t NUM_PIN_CHARS = sizeof(PIN_CHARS) / sizeof(PIN_CHARS[0]);
static const uint32_t NUM_PIN_VALUES = NUM_PIN_CHARS - 1; // ie. not including backspace

static inline char get_pin_value(size_t index)
{
    JADE_ASSERT(index < NUM_PIN_CHARS);
    return PIN_CHARS[index];
}

static void reinitialise_current_pin_digit(pin_insert_t* pin_insert)
{
    JADE_ASSERT(pin_insert);

    switch (pin_insert->initial_state) {
    case ZERO:
        pin_insert->current_selected_value = 0;
        break;
    case POSITION:
        pin_insert->current_selected_value = pin_insert->selected_digit;
        break;
    default:
        pin_insert->current_selected_value = get_uniform_random_byte(NUM_PIN_VALUES);
        break;
    }
}

static void update_digit_node(pin_insert_t* pin_insert, uint8_t i)
{
    JADE_ASSERT(pin_insert);
    JADE_ASSERT(i < PIN_SIZE);

    char strdigit[] = { '\0', '\0' };
    switch (pin_insert->digit_status[i]) {
    case EMPTY:
        gui_set_color(pin_insert->pin_digit_nodes[i].fill_node, TFT_BLACK);
        gui_set_borders(pin_insert->pin_digit_nodes[i].fill_node, TFT_LIGHTGREY, 2, GUI_BORDER_ALL);
        gui_update_text(pin_insert->pin_digit_nodes[i].up_arrow_node, "");
        gui_update_text(pin_insert->pin_digit_nodes[i].down_arrow_node, "");
        break;
    case SELECTED:
        gui_set_color(pin_insert->pin_digit_nodes[i].fill_node, gui_get_highlight_color());
        gui_set_borders(pin_insert->pin_digit_nodes[i].fill_node, gui_get_highlight_color(), 2, GUI_BORDER_ALL);
        gui_update_text(pin_insert->pin_digit_nodes[i].up_arrow_node, "K");
        gui_update_text(pin_insert->pin_digit_nodes[i].down_arrow_node, "L");
        strdigit[0] = PIN_CHARS[pin_insert->current_selected_value];
        break;
    case SET:
        gui_set_color(pin_insert->pin_digit_nodes[i].fill_node, TFT_BLACK);
        gui_set_borders(pin_insert->pin_digit_nodes[i].fill_node, gui_get_highlight_color(), 2, GUI_BORDER_ALL);
        gui_update_text(pin_insert->pin_digit_nodes[i].up_arrow_node, "");
        gui_update_text(pin_insert->pin_digit_nodes[i].down_arrow_node, "");
        strdigit[0] = pin_insert->pin_digits_shown ? PIN_CHARS[pin_insert->pin[i]] : '*';
        break;
    }
    gui_update_text(pin_insert->pin_digit_nodes[i].digit_node, strdigit);
    gui_repaint(pin_insert->pin_digit_nodes[i].fill_node);
}

void make_pin_insert_activity(pin_insert_t* pin_insert, const char* title, const char* message)
{
    JADE_ASSERT(pin_insert);

    pin_insert->activity = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(pin_insert->activity, title, NULL, 0, &pin_insert->title);
    gui_view_node_t* node;

    gui_view_node_t* vsplit;
    if (message) {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_make_text(&node, message, TFT_WHITE);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    } else {
        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 10, 75, 15);
        gui_make_fill(&node, TFT_BLACK);
    }
    gui_set_parent(vsplit, parent);
    gui_set_parent(node, vsplit);

    const size_t toppad = CONFIG_DISPLAY_HEIGHT > 200 ? 20 : CONFIG_DISPLAY_HEIGHT > 160 ? 12 : 4;
    const size_t lrpad = (CONFIG_DISPLAY_WIDTH - (6 * 35)) / 2;
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 6, 35, 35, 35, 35, 35, 35);
    gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, toppad, lrpad, toppad + 8, lrpad);
    gui_set_parent(hsplit, vsplit);

    reinitialise_current_pin_digit(pin_insert);

    for (size_t i = 0; i < PIN_SIZE; ++i) {
        pin_insert->pin[i] = 0xFF;
        pin_insert->digit_status[i] = i == 0 ? SELECTED : EMPTY;

        gui_make_fill(&node, TFT_BLACK);
        gui_set_parent(node, hsplit);
        pin_insert->pin_digit_nodes[i].fill_node = node;

        gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 25, 50, 25);
        gui_set_parent(vsplit, node);
        // no need to store the vsplit

        // Up arrow
        gui_make_text_font(&node, "K", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, vsplit);
        pin_insert->pin_digit_nodes[i].up_arrow_node = node;

        // Digit
        gui_make_text_font(&node, "", TFT_WHITE, DEJAVU24_FONT);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, vsplit);
        gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 5, 0, 0, 0);
        pin_insert->pin_digit_nodes[i].digit_node = node;

        // Down arrow
        gui_make_text_font(&node, "L", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
        gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(node, vsplit);
        pin_insert->pin_digit_nodes[i].down_arrow_node = node;

        update_digit_node(pin_insert, i);
    }
}

static bool next_selected_digit(pin_insert_t* pin_insert)
{
    JADE_ASSERT(pin_insert);
    JADE_ASSERT(pin_insert->selected_digit < PIN_SIZE);

    // make sure the '<' is not selected
    JADE_ASSERT(pin_insert->current_selected_value < 10);

    // copy the value
    pin_insert->pin[pin_insert->selected_digit] = pin_insert->current_selected_value;

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = SET;
    update_digit_node(pin_insert, pin_insert->selected_digit);
    ++pin_insert->selected_digit;

    // reached the last digit - cannot select next, return false
    if (pin_insert->selected_digit >= PIN_SIZE) {
        return false;
    }

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = SELECTED;

    reinitialise_current_pin_digit(pin_insert);
    update_digit_node(pin_insert, pin_insert->selected_digit);

    return true;
}

static bool prev_selected_digit(pin_insert_t* pin_insert)
{
    JADE_ASSERT(pin_insert);
    JADE_ASSERT(pin_insert->selected_digit < PIN_SIZE);

    // at the first digit - cannot select previous, return false
    if (pin_insert->selected_digit == 0) {
        return false;
    }

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = EMPTY;
    update_digit_node(pin_insert, pin_insert->selected_digit);

    --pin_insert->selected_digit;
    reinitialise_current_pin_digit(pin_insert);

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = SELECTED;
    update_digit_node(pin_insert, pin_insert->selected_digit);

    return true;
}

// Returns true if pin entry completes and pin_insert->pin is valid,
// and false if pin entry abandoned and pin_insert->pin is not to be used.
bool run_pin_entry_loop(pin_insert_t* pin_insert)
{
    JADE_ASSERT(pin_insert);
    JADE_ASSERT(pin_insert->activity);

    int32_t ev_id;
    while (true) {
        // wait for a GUI event
        gui_activity_wait_event(pin_insert->activity, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case GUI_WHEEL_LEFT_EVENT:
            pin_insert->current_selected_value
                = (pin_insert->current_selected_value + NUM_PIN_CHARS - 1) % NUM_PIN_CHARS;
            update_digit_node(pin_insert, pin_insert->selected_digit);
            break;
        case GUI_WHEEL_RIGHT_EVENT:
            pin_insert->current_selected_value = (pin_insert->current_selected_value + 1) % NUM_PIN_CHARS;
            update_digit_node(pin_insert, pin_insert->selected_digit);
            break;

        default:
            if (ev_id == gui_get_click_event()) {
                if (get_pin_value(pin_insert->current_selected_value) == CHAR_BACKSPACE) {
                    if (!prev_selected_digit(pin_insert)) {
                        // Returns false when click 'backspace' on first digit (cannot move to previous)
                        return false; // pin entry abandoned
                    }
                } else if (!next_selected_digit(pin_insert)) {
                    // Returns false when click number on last digit (cannot move to next)
                    return true; // pin entry complete
                }
            }
        }
    }
}

void reset_pin(pin_insert_t* pin_insert, const char* title)
{
    JADE_ASSERT(pin_insert);
    // title is optional

    // Select and re-randomise first digit
    pin_insert->selected_digit = 0;
    reinitialise_current_pin_digit(pin_insert);

    // Mark all digits as unset
    for (size_t i = 0; i < PIN_SIZE; ++i) {
        pin_insert->pin[i] = 0xFF;
        pin_insert->digit_status[i] = i == 0 ? SELECTED : EMPTY;
        update_digit_node(pin_insert, i);
    }

    // Update title if passed
    if (title) {
        gui_update_text(pin_insert->title, title);
    }
}

size_t get_pin_as_number(const pin_insert_t* pin_insert)
{
    JADE_ASSERT(pin_insert);
    JADE_ASSERT(pin_insert->selected_digit == PIN_SIZE); // entry complete

    size_t val = 0;
    for (uint8_t i = 0; i < PIN_SIZE; ++i) {
        JADE_ASSERT(pin_insert->digit_status[i] == SET);
        JADE_ASSERT(pin_insert->pin[i] < NUM_PIN_VALUES);

        const size_t digit = pin_insert->pin[i];
        const uint8_t exponent = PIN_SIZE - i - 1;
        val += (digit * pow(10, exponent));
    }

    return val;
}
