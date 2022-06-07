#ifndef UI_H_
#define UI_H_

#include "gui.h"
#include "process.h"

struct wally_tx;

#define NUM_PASSPHRASE_KEYBOARD_SCREENS 4

// Maximum length of message which can be fully displayed on
// 'sign-message' screen - longer messages display the hash
#define MAX_DISPLAY_MESSAGE_LEN 192

#define PIN_SIZE 6

enum pin_digit_status {
    EMPTY,
    SELECTED,
    SET,
};

typedef struct {
    uint8_t pin[PIN_SIZE];
    enum pin_digit_status digit_status[PIN_SIZE];

    uint8_t selected_digit;
    uint8_t current_selected_value;

    gui_activity_t* activity;
    gui_view_node_t* pin_digit_nodes[PIN_SIZE];

    gui_view_node_t* message_node;
} pin_insert_activity_t;

typedef struct {
    bool is_validated_change_address;
    bool is_confidential;
    uint8_t asset_id[32];
    uint8_t blinding_key[33];
    uint64_t value;
    char message[128];
} output_info_t;

typedef struct {
    const uint16_t val;
    const char* txt;
    gui_view_node_t* btn;
} btn_data_t;

// Functions for pin entry
void format_pin(char* buf, uint8_t len, uint8_t pin[PIN_SIZE]);
void make_pin_insert_activity(pin_insert_activity_t** pin_insert_ptr, const char* title, const char* message);
void run_pin_entry_loop(pin_insert_activity_t* pin_insert);
void clear_current_pin(pin_insert_activity_t* pin_insert);

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

// Generic progress-bar screen
void display_progress_bar_activity(const char* title, const char* message, progress_bar_t* progress_bar);
void update_progress_bar(progress_bar_t* progress_bar, size_t total, size_t current);

// Signing-specific screens
void make_confirm_address_activity(gui_activity_t** activity_ptr, const char* address, const char* warning_msg);
void make_sign_message_activity(
    gui_activity_t** activity_ptr, const char* msg_str, size_t msg_len, bool is_hash, const char* path_as_str);
void make_sign_identity_activity(gui_activity_t** activity_ptr, const char* identity, size_t identity_len);

void make_display_output_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info, gui_activity_t** first_activity);
void make_display_elements_output_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info, gui_activity_t** first_activity);
void make_display_final_confirmation_activity(uint64_t fee, const char* warning_msg, gui_activity_t** activity);
void make_display_elements_final_confirmation_activity(
    const char* network, uint64_t fee, const char* warning_msg, gui_activity_t** activity);

#endif /* UI_H_ */
