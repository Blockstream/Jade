#include "../button_events.h"
#include "../jade_assert.h"
#include "../random.h"
#include "../ui.h"
#include "../utils/malloc_ext.h"

static const char CHAR_BACKSPACE = '|';
static const char PIN_CHARS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', CHAR_BACKSPACE };
static const uint32_t NUM_PIN_CHARS = sizeof(PIN_CHARS) / sizeof(PIN_CHARS[0]);
static const uint32_t NUM_PIN_VALUES = NUM_PIN_CHARS - 1; // ie. not including backspace

static inline char get_pin_value(size_t index)
{
    JADE_ASSERT(index < NUM_PIN_CHARS);
    return PIN_CHARS[index];
}

static inline uint8_t get_random_pin_digit(void) { return get_uniform_random_byte(NUM_PIN_VALUES); }

static void update_digit_node(pin_insert_activity_t* pin_insert, uint8_t i)
{
    char str[] = { '\0', '\0' };

    switch (pin_insert->digit_status[i]) {
    case EMPTY:
        gui_set_borders(pin_insert->pin_digit_nodes[i], TFT_LIGHTGREY, 2, GUI_BORDER_ALL);
        break;
    case SELECTED:
        gui_set_borders(pin_insert->pin_digit_nodes[i], TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_ALL);
        str[0] = PIN_CHARS[pin_insert->current_selected_value];
        break;
    case SET:
        gui_set_borders(pin_insert->pin_digit_nodes[i], TFT_BLOCKSTREAM_DARKGREEN, 2, GUI_BORDER_ALL);
        str[0] = '*';
        break;
    }

    gui_update_text(pin_insert->pin_digit_nodes[i], str);
}

void make_pin_insert_activity(pin_insert_activity_t** pin_insert_ptr, const char* title, const char* message)
{
    JADE_ASSERT(pin_insert_ptr);

    *pin_insert_ptr = JADE_CALLOC(1, sizeof(pin_insert_activity_t));
    pin_insert_activity_t* pin_insert = *pin_insert_ptr;

    gui_make_activity(&pin_insert->activity, true, title);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(vsplit, pin_insert->activity->root_node);

    // first row, message
    gui_view_node_t* text_status;
    gui_make_text(&text_status, message, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // second row, pin spinners
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 6, 30, 30, 30, 30, 30, 30);
    gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 30, 12, 30);
    gui_set_parent(hsplit, vsplit);

    pin_insert->current_selected_value = get_random_pin_digit();

    for (size_t i = 0; i < PIN_SIZE; ++i) {
        pin_insert->pin[i] = 0xFF;
        pin_insert->digit_status[i] = i == 0 ? SELECTED : EMPTY;

        gui_view_node_t* fill;
        gui_make_fill(&fill, TFT_BLACK);
        gui_set_parent(fill, hsplit);

        gui_make_text_font(&pin_insert->pin_digit_nodes[i], "", TFT_WHITE, DEJAVU24_FONT);
        gui_set_align(pin_insert->pin_digit_nodes[i], GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(pin_insert->pin_digit_nodes[i], fill);

        update_digit_node(pin_insert, i);
    }
}

static bool next_selected_digit(pin_insert_activity_t* pin_insert)
{
    // make sure the '<' is not selected
    JADE_ASSERT(pin_insert->current_selected_value < 10);

    // copy the value
    pin_insert->pin[pin_insert->selected_digit] = pin_insert->current_selected_value;

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = SET;
    update_digit_node(pin_insert, pin_insert->selected_digit);

    pin_insert->selected_digit++;
    pin_insert->current_selected_value = get_random_pin_digit();

    // finally reached the last digit
    if (pin_insert->selected_digit >= PIN_SIZE) {
        return true;
    }

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = SELECTED;
    update_digit_node(pin_insert, pin_insert->selected_digit);

    return false;
}

static void prev_selected_digit(pin_insert_activity_t* pin_insert)
{
    if (pin_insert->selected_digit == 0) {
        return;
    }

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = EMPTY;
    update_digit_node(pin_insert, pin_insert->selected_digit);

    pin_insert->selected_digit--;
    pin_insert->current_selected_value = get_random_pin_digit();

    // set the status and update the ui
    pin_insert->digit_status[pin_insert->selected_digit] = SELECTED;
    update_digit_node(pin_insert, pin_insert->selected_digit);
}

static void next_value(pin_insert_activity_t* pin_insert)
{
    // Do not show '<' on first pin digit
    const uint8_t digit_value_ceiling = pin_insert->selected_digit == 0 ? NUM_PIN_VALUES : NUM_PIN_CHARS;
    pin_insert->current_selected_value = (pin_insert->current_selected_value + 1) % digit_value_ceiling;

    // TODO: skip < if selected_digit == 0
    update_digit_node(pin_insert, pin_insert->selected_digit);
}

static void prev_value(pin_insert_activity_t* pin_insert)
{
    // Do not show '<' on first pin digit
    const uint8_t digit_value_ceiling = pin_insert->selected_digit == 0 ? NUM_PIN_VALUES : NUM_PIN_CHARS;
    pin_insert->current_selected_value
        = (digit_value_ceiling + pin_insert->current_selected_value - 1) % digit_value_ceiling;

    // TODO: skip < if selected_digit == 0
    update_digit_node(pin_insert, pin_insert->selected_digit);
}

void run_pin_entry_loop(pin_insert_activity_t* pin_insert)
{
    int ev_id;
    while (true) {
        // wait for a GUI event
        gui_activity_wait_event(pin_insert->activity, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case GUI_WHEEL_LEFT_EVENT:
            prev_value(pin_insert);
            break;
        case GUI_WHEEL_RIGHT_EVENT:
            next_value(pin_insert);
            break;

        default:
            if (ev_id == gui_get_click_event()) {
                if (get_pin_value(pin_insert->current_selected_value) == CHAR_BACKSPACE) {
                    prev_selected_digit(pin_insert);
                    continue;
                }

                // Returns true when click on last digit
                if (next_selected_digit(pin_insert)) {
                    return;
                }
            }
        }
    }
}

void clear_current_pin(pin_insert_activity_t* pin_insert)
{
    pin_insert->selected_digit = 0;
    pin_insert->current_selected_value = get_random_pin_digit();

    for (size_t i = 0; i < PIN_SIZE; ++i) {
        pin_insert->pin[i] = 0xFF;
        pin_insert->digit_status[i] = i == 0 ? SELECTED : EMPTY;

        update_digit_node(pin_insert, i);
    }
}
