#ifndef UI_H_
#define UI_H_

#include "assets.h"
#include "gui.h"

struct wally_tx;

// Maximum length of message which can be fully displayed on
// 'sign-message' screen - longer messages display the hash
#define MAX_DISPLAY_MESSAGE_LEN 192

// Keyboard entry screens
#define MAX_KB_ENTRY_LEN 256

// NOTE: final value is a sentinel/count, not a valid enum value
typedef enum {
    KB_LOWER_CASE_CHARS = 0,
    KB_UPPER_CASE_CHARS,
    KB_NUMBERS_SYMBOLS,
    KB_REMAINING_SYMBOLS,
    NUM_KBS
} keyboard_type_t;

typedef struct {
    char strdata[MAX_KB_ENTRY_LEN];
    size_t max_allowed_len;
    size_t len;

    keyboard_type_t keyboards[NUM_KBS];
    size_t num_kbs;
    size_t current_kb;

    gui_activity_t* activity;
    gui_view_node_t* textbox_nodes[NUM_KBS];
} keyboard_entry_t;

// PIN entry
#define PIN_SIZE 6

enum pin_digit_status {
    EMPTY,
    SELECTED,
    SET,
};

typedef struct {
    gui_view_node_t* fill_node;
    gui_view_node_t* up_arrow_node;
    gui_view_node_t* digit_node;
    gui_view_node_t* down_arrow_node;
} pin_digit_t;

typedef struct {
    uint8_t pin[PIN_SIZE];
    enum pin_digit_status digit_status[PIN_SIZE];

    gui_activity_t* activity;
    gui_view_node_t* title;

    pin_digit_t pin_digit_nodes[PIN_SIZE];

    uint8_t selected_digit;
    uint8_t current_selected_value;
} pin_insert_t;

#define OUTPUT_FLAG_CONFIDENTIAL 1
#define OUTPUT_FLAG_HAS_BLINDING_KEY 2
#define OUTPUT_FLAG_VALIDATED 4
#define OUTPUT_FLAG_CHANGE 8
#define OUTPUT_FLAG_HAS_UNBLINDED 16

typedef struct {
    char message[128];
    uint8_t blinding_key[33];
    uint8_t asset_id[32];
    uint64_t value;
    uint8_t flags;
} output_info_t;

typedef struct {
    uint8_t asset_id[32];
    uint64_t value;
    uint64_t validated_value;
} movement_summary_info_t;

// Progress bar
typedef struct {
    bool transparent;
    gui_view_node_t* container;
    gui_view_node_t* progress_bar;
    gui_view_node_t* pcnt_txt;
    uint8_t percent_last_value;
} progress_bar_t;

// Button bars/menus etc.
typedef enum { UI_ROW, UI_COLUMN } ui_button_layout_t;

typedef struct {
    gui_view_node_t* btn;
    gui_view_node_t* content;
    const char* txt;
    uint32_t font;
    uint32_t ev_id;
    uint8_t borders;
} btn_data_t;

// Helper to update dynamic menu item label (name: value)
void update_menu_item(gui_view_node_t* node, const char* label, const char* value);

// Helper to create an even split
gui_view_node_t* make_even_split(ui_button_layout_t layout, uint8_t num_splits);

// Helpers to create standard (look and feel) buttons in a row or column
void add_button(gui_view_node_t* parent, btn_data_t* btn_info);
void add_buttons(gui_view_node_t* parent, ui_button_layout_t layout, btn_data_t* btns, size_t num_btns);

// Helpers to create and populate the common title bar
void populate_title_bar(
    gui_view_node_t* bar, const char* title, btn_data_t* btns, size_t num_btns, gui_view_node_t** title_node);
gui_view_node_t* add_title_bar(
    gui_activity_t* activity, const char* title, btn_data_t* btns, size_t num_btns, gui_view_node_t** title_node);

// Helper to create an activity which is a grid of (up to 5x5) text items
gui_activity_t* make_text_grid_activity(const char* title, btn_data_t* hdrbtns, size_t num_hdrbtns, size_t toppad,
    uint8_t xcells, uint8_t ycells, const char* texts, size_t num_texts, const char** remaining_texts);

// Helper to create a vertical menu of 2, 3 or 4 buttons
gui_activity_t* make_menu_activity(
    const char* title, btn_data_t* hdrbtns, const size_t num_hdrbtns, btn_data_t* menubtns, size_t num_menubtns);

// Helper to create an activity to show a message on a single central label
gui_activity_t* make_show_message_activity(const char* message[], size_t message_size, const char* title,
    btn_data_t* hdrbtns, size_t num_hdrbtns, btn_data_t* ftrbtns, size_t num_ftrbtns);

// Activity to show a single value
gui_activity_t* make_show_single_value_activity(const char* name, const char* value, const bool show_helpbtn);

// Make activity that displays a simple message - cannot be dismissed by caller
gui_activity_t* display_message_activity(const char* message[], size_t message_size);
gui_activity_t* display_processing_message_activity();

// Run activity that displays a message and awaits an 'ack' button click
void await_message_activity(const char* message[], size_t message_size);
void await_error_activity(const char* message[], size_t message_size);

// Activity that displays a message and awaits a 'Yes'/'Continue' or 'No'/'Skip'/'Back' event
bool await_yesno_activity(
    const char* title, const char* message[], size_t message_size, bool default_selection, const char* help_url);
bool await_skipyes_activity(
    const char* title, const char* message[], size_t message_size, bool default_selection, const char* help_url);
bool await_continueback_activity(
    const char* title, const char* message[], size_t message_size, bool default_selection, const char* help_url);

// Updatable label with left/right arrows
gui_activity_t* make_carousel_activity(const char* title, gui_view_node_t** label, gui_view_node_t** item);
void update_carousel_highlight_color(const gui_view_node_t* text_label, color_t color, bool repaint);

// Functions for keyboard entry
void make_keyboard_entry_activity(keyboard_entry_t* kb_entry, const char* title);
void run_keyboard_entry_loop(keyboard_entry_t* kb_entry);

// Functions for pin entry
void make_pin_insert_activity(pin_insert_t* pin_insert, const char* title, const char* message);
bool run_pin_entry_loop(pin_insert_t* pin_insert);
void reset_pin(pin_insert_t* pin_insert, const char* title);

// Generic progress-bar
void make_progress_bar(gui_view_node_t* parent, progress_bar_t* progress_bar);
gui_activity_t* make_progress_bar_activity(const char* title, const char* message, progress_bar_t* progress_bar);
void update_progress_bar(progress_bar_t* progress_bar, size_t total, size_t current);

#endif /* UI_H_ */
