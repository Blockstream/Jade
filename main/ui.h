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
    uint8_t pin[PIN_SIZE];
    enum pin_digit_status digit_status[PIN_SIZE];

    gui_activity_t* activity;
    gui_view_node_t* pin_digit_nodes[PIN_SIZE];

    uint8_t selected_digit;
    uint8_t current_selected_value;
} pin_insert_t;

typedef struct {
    bool is_validated_change_address;
    bool is_confidential;
    uint8_t asset_id[32];
    uint8_t blinding_key[33];
    uint64_t value;
    char message[128];
} output_info_t;

// Progress bar
typedef struct {
    gui_view_node_t* progress_bar;
    gui_view_node_t* pcnt_txt;
    uint8_t percent_last_value;
} progress_bar_t;

typedef struct {
    const char* txt;
    uint32_t font;
    uint32_t ev_id;
    uint32_t val;
    gui_view_node_t* btn;
} btn_data_t;

// Helper to create up to four buttons in a row or column
typedef enum { UI_ROW, UI_COLUMN } ui_button_layout_t;
void add_buttons(gui_view_node_t* parent, ui_button_layout_t layout, btn_data_t* btns, size_t num_btns);

// Functions for keyboard entry
void make_keyboard_entry_activity(keyboard_entry_t* kb_entry, const char* title);
void run_keyboard_entry_loop(keyboard_entry_t* kb_entry);

// Functions for pin entry
void make_pin_insert_activity(pin_insert_t* pin_insert, const char* title, const char* message);
void run_pin_entry_loop(pin_insert_t* pin_insert);
void clear_current_pin(pin_insert_t* pin_insert);

// Functions for pinserver details
void make_confirm_pinserver_details_activity(
    gui_activity_t** activity_ptr, const char* urlA, const char* urlB, const char* pubkeyhex);
void make_confirm_pinserver_certificate_activity(gui_activity_t** activity_ptr, const char* cert_hash_hex);

// View/delete multisig registration
void make_view_multisig_activity(gui_activity_t** activity_ptr, const char* multisig_name, size_t index, size_t total,
    bool valid, bool sorted, size_t threshold, size_t num_signers, const uint8_t* master_blinding_key,
    size_t master_blinding_key_len);

// Generic message screens which may await a button click
gui_activity_t* display_message_activity(const char* message);
gui_activity_t* display_message_activity_two_lines(const char* msg_first, const char* msg_second);
void await_message_activity(const char* message);
void await_error_activity(const char* errormessage);
bool await_yesno_activity(const char* title, const char* message, bool default_selection);

// Generic progress-bar
void make_progress_bar(gui_view_node_t* parent, progress_bar_t* progress_bar);
void display_progress_bar_activity(const char* title, const char* message, progress_bar_t* progress_bar);
void update_progress_bar(progress_bar_t* progress_bar, size_t total, size_t current);

// Signing-specific screens
void make_confirm_address_activity(gui_activity_t** activity_ptr, const char* address, const char* warning_msg);
void make_sign_message_activity(
    gui_activity_t** activity_ptr, const char* msg_str, size_t msg_len, bool is_hash, const char* path_as_str);
void make_sign_identity_activity(gui_activity_t** activity_ptr, const char* identity, size_t identity_len);

void make_display_output_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info, gui_activity_t** first_activity);
void make_display_elements_output_activity(const char* network, const struct wally_tx* tx,
    const output_info_t* output_info, const asset_info_t* assets, const size_t num_assets,
    gui_activity_t** first_activity);
void make_display_final_confirmation_activity(uint64_t fee, const char* warning_msg, gui_activity_t** activity);
void make_display_elements_final_confirmation_activity(
    const char* network, uint64_t fee, const char* warning_msg, gui_activity_t** activity);

#endif /* UI_H_ */
