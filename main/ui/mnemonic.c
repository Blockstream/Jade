#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

#define NUM_KEYBOARD_ROWS 3

void gen_btns(gui_view_node_t* parent, const size_t num_buttons, const char* msgs[], const uint32_t fonts[],
    const int32_t ev_ids[], gui_view_node_t* out_btns[]);

static void make_mnemonic_screen(gui_activity_t** activity_ptr, const char* header, const char* msg,
    const size_t num_btns, const char* btn_msg[], const uint32_t btn_font[], const int32_t btn_ev_id[],
    gui_view_node_t* out_btns[])
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, header);
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 66, 34);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t* text_status;
    gui_make_text(&text_status, msg, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, button
    gen_btns(vsplit, num_btns, btn_msg, btn_font, btn_ev_id, out_btns);
}

void make_mnemonic_welcome_screen(gui_activity_t** activity_ptr)
{
    // First btn looks like '<-' on button
    const char* btn_msg[] = { "=", "New", "Recover" };
    const uint32_t btn_font[] = { JADE_SYMBOLS_16x16_FONT, GUI_DEFAULT_FONT, GUI_DEFAULT_FONT };
    const int32_t btn_ev_id[] = { BTN_MNEMONIC_EXIT, BTN_NEW_MNEMONIC, BTN_RECOVER_MNEMONIC };
    gui_view_node_t* btns[sizeof(btn_msg) / sizeof(btn_msg[0])];
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!",
        "Do you want to create a new\nwallet, or recover an existing\nwallet?", 3, btn_msg, btn_font, btn_ev_id, btns);

    // Set the intially selected item to the 'New' button
    gui_set_activity_initial_selection(*activity_ptr, btns[1]);
}

void make_new_mnemonic_screen(gui_activity_t** activity_ptr)
{
    const char* btn_msg[] = { "12 words", "Advanced" };
    const int32_t btn_ev_id[] = { BTN_NEW_MNEMONIC_12_BEGIN, BTN_NEW_MNEMONIC_ADVANCED };
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!",
        "A new recovery phrase will be\ngenerated.\nWrite these words down and\nstore them somewhere safe", 2, btn_msg,
        NULL, btn_ev_id, NULL);
}

void make_new_mnemonic_screen_advanced(gui_activity_t** activity_ptr)
{
    const char* btn_msg[] = { "12 words", "24 words" };
    const int32_t btn_ev_id[] = { BTN_NEW_MNEMONIC_12_BEGIN, BTN_NEW_MNEMONIC_24_BEGIN };
    make_mnemonic_screen(
        activity_ptr, "Welcome to Jade!", "\nSelect recovery phrase length", 2, btn_msg, NULL, btn_ev_id, NULL);
}

void make_mnemonic_recovery_screen(gui_activity_t** activity_ptr)
{
    const char* btn_msg[] = { "12 words", "Advanced" };
    const int32_t btn_ev_id[] = { BTN_RECOVER_MNEMONIC_12_BEGIN, BTN_RECOVER_MNEMONIC_ADVANCED };
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!", "\nHow would you like to\nrecover the wallet?", 2, btn_msg,
        NULL, btn_ev_id, NULL);
}

void make_mnemonic_recovery_screen_advanced(gui_activity_t** activity_ptr)
{
    const char* btn_msg[] = { "12 words", "24 words", "Scan QR" };
    const int32_t btn_ev_id[] = { BTN_RECOVER_MNEMONIC_12_BEGIN, BTN_RECOVER_MNEMONIC_24_BEGIN, BTN_QR_MNEMONIC_BEGIN };
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!", "\nSelect recovery phrase length\nor to scan a QR code", 3,
        btn_msg, NULL, btn_ev_id, NULL);
}

static void make_mnemonic_page(gui_activity_t** activity_ptr, const size_t nwords, const size_t first_index,
    char* word1, char* word2, char* word3, char* word4, gui_view_node_t* out_btns[])
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(word1);
    JADE_ASSERT(word2);
    JADE_ASSERT(word3);
    JADE_ASSERT(word4);
    JADE_ASSERT(out_btns);

    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(first_index % 4 == 0);

    gui_make_activity(activity_ptr, true, "Recovery Phrase");
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 30, 30, 34);
    gui_set_parent(vsplit, act->root_node);

    // first four rows: the words prefixed by their index, e.g. "1: river"
    char msg[64];
    char* words[] = { word1, word2, word3, word4 };

    gui_view_node_t* hsplit1;
    gui_make_hsplit(&hsplit1, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit1, vsplit);

    gui_view_node_t* hsplit2;
    gui_make_hsplit(&hsplit2, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit2, vsplit);

    for (int i = 0; i < 2; ++i) {
        const int ret = snprintf(msg, sizeof(msg), "%2u: %s", first_index + i + 1, words[i]);
        JADE_ASSERT(ret > 0 && ret < sizeof(msg));

        gui_view_node_t* text_status;
        gui_make_text_font(&text_status, msg, TFT_WHITE, UBUNTU16_FONT);
        gui_set_text_noise(text_status, TFT_BLACK);
        gui_set_parent(text_status, hsplit1);
        gui_set_align(text_status, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    }

    for (int i = 2; i < 4; ++i) {
        const int ret = snprintf(msg, sizeof(msg), "%2u: %s", first_index + i + 1, words[i]);
        JADE_ASSERT(ret > 0 && ret < sizeof(msg));

        gui_view_node_t* text_status;
        gui_make_text_font(&text_status, msg, TFT_WHITE, UBUNTU16_FONT);
        gui_set_text_noise(text_status, TFT_BLACK);
        gui_set_parent(text_status, hsplit2);
        gui_set_align(text_status, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    }

    // second row, buttons - '<-' and '->'
    if (first_index == 0) {
        // First page, the 'back' button raises 'exit' event
        const char* btn_msg[2] = { "=", ">" };
        const uint32_t btn_fonts[2] = { JADE_SYMBOLS_16x16_FONT, JADE_SYMBOLS_16x16_FONT };
        const int32_t btn_ev_id[2] = { BTN_MNEMONIC_EXIT, BTN_MNEMONIC_NEXT };
        gen_btns(vsplit, 2, btn_msg, btn_fonts, btn_ev_id, out_btns);
    } else if (first_index == nwords - 4) {
        // Last page, the tick button raises 'verify' event
        const char* btn_msg[2] = { "=", "S" };
        const uint32_t btn_fonts[2] = { JADE_SYMBOLS_16x16_FONT, VARIOUS_SYMBOLS_FONT };
        const int32_t btn_ev_id[2] = { BTN_MNEMONIC_PREV, BTN_MNEMONIC_VERIFY };
        gen_btns(vsplit, 2, btn_msg, btn_fonts, btn_ev_id, out_btns);
    } else {
        // Otherwise 'prev' and 'next' events
        const char* btn_msg[2] = { "=", ">" };
        const uint32_t btn_fonts[2] = { JADE_SYMBOLS_16x16_FONT, JADE_SYMBOLS_16x16_FONT };
        const int32_t btn_ev_id[2] = { BTN_MNEMONIC_PREV, BTN_MNEMONIC_NEXT };
        gen_btns(vsplit, 2, btn_msg, btn_fonts, btn_ev_id, out_btns);
    }
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 0);

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(*activity_ptr, out_btns[1]);
}

void make_show_mnemonic(
    gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[], const size_t nwords)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(first_activity_ptr);
    JADE_ASSERT(last_activity_ptr);

    gui_activity_t* prev_act = NULL;
    gui_view_node_t* prev_btn = NULL;

    const size_t npages = nwords / 4; // 4 words per page
    for (size_t j = 0; j < npages; j++) {
        gui_view_node_t* btns[2];
        gui_activity_t* this = NULL;

        make_mnemonic_page(
            &this, nwords, j * 4, words[j * 4], words[j * 4 + 1], words[j * 4 + 2], words[j * 4 + 3], btns);

        if (prev_act) {
            gui_connect_button_activity(btns[0], prev_act);
            gui_connect_button_activity(prev_btn, this);
        }

        if (!*first_activity_ptr) {
            *first_activity_ptr = this;
        }

        prev_act = this;
        prev_btn = btns[1];
    }

    *last_activity_ptr = prev_act;
}

static void make_confirm_mnemonic_page(
    gui_activity_t** activity_ptr, gui_view_node_t** text_box, size_t confirm_index, char* word_prev, char* word_next)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(text_box);

    JADE_LOGD("Confirm page index %u, prev %s, next %s", confirm_index, word_prev, word_next);

    gui_make_activity(activity_ptr, true, "Backup check");
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, act->root_node);

    // first row, hint index
    char hint_str[32];
    const int ret = snprintf(hint_str, sizeof(hint_str), "Confirm word %u", confirm_index + 1);
    JADE_ASSERT(ret > 0 && ret < sizeof(hint_str));

    gui_view_node_t* hint;
    gui_make_text(&hint, hint_str, TFT_WHITE);
    gui_set_parent(hint, vsplit);
    gui_set_align(hint, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // second row, previous word
    gui_view_node_t* prev_hsplit;
    gui_make_hsplit(&prev_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(prev_hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(prev_hsplit, vsplit);

    char prev_str[16];
    const int prev_ret = snprintf(prev_str, sizeof(prev_str), "%u", confirm_index);
    JADE_ASSERT(prev_ret > 0 && prev_ret < sizeof(prev_str));

    gui_view_node_t* prev_left;
    gui_make_text(&prev_left, prev_str, TFT_WHITE);
    gui_set_align(prev_left, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(prev_left, prev_hsplit);

    gui_view_node_t* prev_center;
    gui_make_text(&prev_center, word_prev, TFT_WHITE);
    gui_set_text_noise(prev_center, TFT_BLACK);
    gui_set_align(prev_center, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(prev_center, prev_hsplit);

    gui_view_node_t* prev_right;
    gui_make_text(&prev_right, "", TFT_WHITE);
    gui_set_align(prev_right, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(prev_right, prev_hsplit);

    // third row
    gui_view_node_t* words_hsplit;
    gui_make_hsplit(&words_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(words_hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(words_hsplit, vsplit);

    gui_view_node_t* text_left;
    gui_make_text(&text_left, "=", TFT_WHITE);
    gui_set_text_font(text_left, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_left, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_left, words_hsplit);

    // This textbox will be updated so we add a black bg that will be repainted every time to clean the previous string
    gui_view_node_t* black_bg;
    gui_make_fill(&black_bg, TFT_BLACK);
    gui_set_parent(black_bg, words_hsplit);
    gui_view_node_t* text_select;
    gui_make_text(&text_select, "", TFT_WHITE);
    gui_set_text_noise(text_select, TFT_BLACK);
    gui_set_align(text_select, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_select, black_bg);
    gui_set_borders(text_select, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_ALL);
    *text_box = text_select;

    gui_view_node_t* text_right;
    gui_make_text(&text_right, ">", TFT_WHITE);
    gui_set_text_font(text_right, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_right, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_right, words_hsplit);

    // fourth row, following word
    gui_view_node_t* follow_hsplit;
    gui_make_hsplit(&follow_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(follow_hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(follow_hsplit, vsplit);

    char follow_str[16];
    const int follow_ret = snprintf(follow_str, sizeof(follow_str), "%u", confirm_index + 2);
    JADE_ASSERT(follow_ret > 0 && follow_ret < sizeof(follow_str));

    gui_view_node_t* follow_left;
    gui_make_text(&follow_left, follow_str, TFT_WHITE);
    gui_set_align(follow_left, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(follow_left, follow_hsplit);

    gui_view_node_t* follow_center;
    gui_make_text(&follow_center, word_next, TFT_WHITE);
    gui_set_text_noise(follow_center, TFT_BLACK);
    gui_set_align(follow_center, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(follow_center, follow_hsplit);

    gui_view_node_t* follow_right;
    gui_make_text(&follow_right, "", TFT_WHITE);
    gui_set_align(follow_right, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(follow_right, follow_hsplit);
}

void make_confirm_mnemonic_screen(gui_activity_t** activity_ptr, gui_view_node_t** text_box_ptr, const size_t confirm,
    char* words[], const size_t nwords)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(text_box_ptr);
    JADE_ASSERT(confirm > 0 && confirm < nwords - 1); // Must be able to access next and previous entries
    make_confirm_mnemonic_page(activity_ptr, text_box_ptr, confirm, words[confirm - 1], words[confirm + 1]);
}

// recover
void make_recover_word_page(gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** backspace,
    gui_view_node_t** enter, gui_view_node_t** keys, const size_t keys_len)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(textbox);
    JADE_ASSERT(backspace);
    JADE_ASSERT(enter);
    JADE_ASSERT(keys);
    JADE_ASSERT(keys_len == 26); // ie. A->Z

    gui_make_activity(activity_ptr, true, "Enter Word");
    gui_activity_t* act = *activity_ptr;
    act->selectables_wrap = true; // allow the button cursor to wrap

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* text_status;
    gui_make_text(&text_status, "", TFT_WHITE);
    gui_set_text_noise(text_status, TFT_BLACK);
    gui_set_parent(text_status, text_bg);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 1, 0);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    *textbox = text_status;

    // second row, keyboard
    char* lines[NUM_KEYBOARD_ROWS];
    lines[0] = (char[]){ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J' };
    lines[1] = (char[]){ 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S' };
    lines[2] = (char[]){ 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '|' };
    const size_t sizes[NUM_KEYBOARD_ROWS] = { 10, 9, 9 };

    for (size_t l = 0; l < NUM_KEYBOARD_ROWS; ++l) {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 10, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24);
        gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, (l * 8)); // offset each row slightly
        gui_set_parent(hsplit, vsplit);

        for (size_t c = 0; c < sizes[l]; ++c) {
            size_t btn_ev_id;
            if (lines[l][c] >= 'A' && lines[l][c] <= 'Z') {
                btn_ev_id = BTN_KEYBOARD_ASCII_OFFSET + lines[l][c];
            } else if (lines[l][c] == '|') {
                btn_ev_id = BTN_KEYBOARD_BACKSPACE;
            } else if (lines[l][c] == ' ') {
                btn_ev_id = BTN_KEYBOARD_ENTER;
            } else {
                JADE_ASSERT_MSG(false, "Unknown button %c", lines[l][c]);
            }

            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, btn_ev_id, NULL);
            gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn, TFT_BLUE, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_borders_inactive_color(btn, TFT_BLACK);
            gui_set_parent(btn, hsplit);

            if (lines[l][c] >= 'A' && lines[l][c] <= 'Z') {
                const size_t index = lines[l][c] - 'A';
                JADE_ASSERT(index < keys_len);
                keys[index] = btn;
            } else if (lines[l][c] == '|') {
                *backspace = btn;
            } else if (lines[l][c] == ' ') {
                gui_set_borders(btn, TFT_DARKGREY, 2, 0);
                *enter = btn;
            }

            gui_view_node_t* label;
            const char str[2] = { lines[l][c], 0 };
            gui_make_text(&label, str, TFT_WHITE);
            gui_set_parent(label, btn);
            gui_set_align(label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }
    }
}

void make_recover_word_page_select10(gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** status)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(textbox);

    gui_make_activity(activity_ptr, true, "Recover Wallet");
    gui_activity_t* act = *activity_ptr;
    act->selectables_wrap = true; // allow the button cursor to wrap

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* text_status;
    gui_make_text(&text_status, "", TFT_WHITE);
    gui_set_parent(text_status, text_bg);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 1, 0);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    *status = text_status;

    // second row,
    gui_view_node_t* padding_hsplit;
    gui_make_hsplit(&padding_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(padding_hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(padding_hsplit, vsplit);

    // Third row, words
    gui_view_node_t* words_hsplit;
    gui_make_hsplit(&words_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(words_hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(words_hsplit, vsplit);

    gui_view_node_t* text_left;
    gui_make_text(&text_left, "=", TFT_WHITE);
    gui_set_text_font(text_left, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_left, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_left, words_hsplit);

    // This textbox will be updated so we add a black bg that will be repainted every time to clean the previous string
    gui_view_node_t* black_bg;
    gui_make_fill(&black_bg, TFT_BLACK);
    gui_set_parent(black_bg, words_hsplit);
    gui_view_node_t* text_select;
    gui_make_text(&text_select, "", TFT_WHITE);
    gui_set_text_noise(text_select, TFT_BLACK);
    gui_set_align(text_select, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_select, black_bg);
    gui_set_borders(text_select, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_ALL);
    *textbox = text_select;

    gui_view_node_t* text_right;
    gui_make_text(&text_right, ">", TFT_WHITE);
    gui_set_text_font(text_right, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_right, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_right, words_hsplit);

    // Fourth row
    gui_view_node_t* buttons_hsplit;
    gui_make_hsplit(&buttons_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(buttons_hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(buttons_hsplit, vsplit);
}

void make_mnemonic_qr_scan(gui_activity_t** activity_ptr, gui_view_node_t** camera_node, gui_view_node_t** textbox)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(camera_node);
    JADE_ASSERT(textbox);

    // this is a weird activity and we need the full screen height for the camera, so we disable the status bar and
    // re-do it ourselves
    gui_make_activity(activity_ptr, false, NULL);
    gui_activity_t* act = *activity_ptr;

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, act->root_node);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 38, 23, 23);
    gui_set_parent(vsplit, hsplit);

    gui_view_node_t* camera_fill;
    gui_make_picture(&camera_fill, NULL);
    gui_set_parent(camera_fill, hsplit);
    *camera_node = camera_fill;

    // first row, header
    gui_view_node_t* text1;
    gui_make_text(&text1, "Scan a QR", TFT_WHITE);
    gui_set_parent(text1, vsplit);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text1, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    // second row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* text_status;
    gui_make_text(&text_status, "", TFT_WHITE);
    gui_set_parent(text_status, text_bg);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);
    *textbox = text_status;

    // third row: scan button
    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_QR_MNEMONIC_SCAN, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, vsplit);

    gui_view_node_t* btn1_text;
    gui_make_text(&btn1_text, "Scan", TFT_WHITE);
    gui_set_align(btn1_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(btn1_text, btn1);

    // fourth row: exit button
    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_QR_MNEMONIC_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, vsplit);

    gui_view_node_t* btn2_text;
    gui_make_text(&btn2_text, "Exit", TFT_WHITE);
    gui_set_align(btn2_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(btn2_text, btn2);
}

// enter passphrase
static void make_enter_passphrase_page(
    link_activity_t* kb_screen_activity, const size_t page, gui_view_node_t** textbox)
{
    JADE_ASSERT(kb_screen_activity);
    JADE_ASSERT(page < NUM_PASSPHRASE_KEYBOARD_SCREENS);
    JADE_ASSERT(textbox);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Enter Passphrase");
    act->selectables_wrap = true; // allow the button cursor to wrap

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* text_status;
    gui_make_text(&text_status, "", TFT_WHITE);
    gui_set_text_noise(text_status, TFT_BLACK);
    gui_set_parent(text_status, text_bg);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 1, 0);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    *textbox = text_status;

    // second row, keyboard
    char* lines[NUM_KEYBOARD_ROWS];
    size_t sizes[NUM_KEYBOARD_ROWS] = { 10, 9, 10 };
    // NOTE: final three characters ('|', '>', 'S') are rendered in different symbols fonts
    // and are buttons for 'backspace', 'shift/next kb', and 'enter/done'  (see below)
    if (page == 0) {
        lines[0] = (char[]){ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j' };
        lines[1] = (char[]){ 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's' };
        lines[2] = (char[]){ 't', 'u', 'v', 'w', 'x', 'y', 'z', '|', '>', 'S' };
        // 'sizes' ok
    } else if (page == 1) {
        lines[0] = (char[]){ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J' };
        lines[1] = (char[]){ 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S' };
        lines[2] = (char[]){ 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '|', '>', 'S' };
        // 'sizes' ok
    } else if (page == 2) {
        lines[0] = (char[]){ '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };
        lines[1] = (char[]){ '!', '"', '#', '$', '%', '&', '\'', '(', ')' };
        lines[2] = (char[]){ '*', '+', ',', '-', '.', '/', '|', '>', 'S' };
        sizes[2] = 9;
    } else if (page == 3) {
        lines[0] = (char[]){ ':', ';', '<', '=', '>', '?', '@' };
        lines[1] = (char[]){ '[', '\\', ']', '^', '_', '`', '~' };
        lines[2] = (char[]){ '{', '|', '}', ' ', '|', '>', 'S' };
        sizes[0] = 7;
        sizes[1] = 7;
        sizes[2] = 7;
    } else {
        JADE_ASSERT_MSG(false, "Unhandled keyboard screen %d", page);
    }

    gui_view_node_t* btnShift = NULL;
    for (size_t l = 0; l < NUM_KEYBOARD_ROWS; ++l) {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 10, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24);
        gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0,
            ((10 - sizes[l]) * 10)); // offset each row depending on row length
        gui_set_parent(hsplit, vsplit);

        // Create 'keys'
        for (size_t c = 0; c < sizes[l]; ++c) {
            // By default the 'event' is based on the ascii character displayed
            size_t btn_ev_id = BTN_KEYBOARD_ASCII_OFFSET + lines[l][c];
            size_t font = UBUNTU16_FONT;

            // The last three buttons on the last row are exceptions
            // These are buttons for 'backspace', 'shift/next kb', and 'enter/done'
            // They are rendered in different fonts to display bespoke symbols,
            // and raise events specific to these actions.
            if (l == NUM_KEYBOARD_ROWS - 1 && c >= sizes[l] - 3) {
                if (c == sizes[l] - 3) {
                    btn_ev_id = BTN_KEYBOARD_BACKSPACE;
                    font = DEFAULT_FONT; // '|' becomes <backspace>
                } else if (c == sizes[l] - 2) {
                    btn_ev_id = BTN_KEYBOARD_SHIFT;
                    font = JADE_SYMBOLS_16x16_FONT; // '>' becomes <right arrow>
                } else if (c == sizes[l] - 1) {
                    btn_ev_id = BTN_KEYBOARD_ENTER;
                    font = VARIOUS_SYMBOLS_FONT; // 'S' becomes <tick>
                }
            }

            gui_view_node_t* btn;
            gui_make_button(&btn, TFT_BLACK, btn_ev_id, NULL);
            gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn, TFT_BLUE, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
            gui_set_borders_inactive_color(btn, TFT_BLACK);
            gui_set_parent(btn, hsplit);

            gui_view_node_t* label;
            const char str[2] = { lines[l][c], 0 };
            gui_make_text(&label, str, TFT_WHITE);
            gui_set_text_font(label, font);
            gui_set_parent(label, btn);
            gui_set_align(label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

            // 'Shift' button to move to next kb screen
            if (btn_ev_id == BTN_KEYBOARD_SHIFT) {
                btnShift = btn;
            }
        }
    }

    // Push details into the output structure
    kb_screen_activity->activity = act;
    kb_screen_activity->prev_button = NULL; // Add one ?
    kb_screen_activity->next_button = btnShift;
}

void make_enter_passphrase_screen(
    gui_activity_t** activity_ptr, gui_view_node_t* textboxes[], const size_t textboxes_len)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(textboxes);
    JADE_ASSERT(textboxes_len == NUM_PASSPHRASE_KEYBOARD_SCREENS);

    // Chain the loop of kb screen activities
    link_activity_t kb_screen_act;
    linked_activities_info_t act_info
        = { .first_activity = NULL, .last_activity = NULL, .last_activity_next_button = NULL };

    for (size_t i = 0; i < NUM_PASSPHRASE_KEYBOARD_SCREENS; ++i) {
        make_enter_passphrase_page(&kb_screen_act, i, &textboxes[i]);
        gui_chain_activities(&kb_screen_act, &act_info);
    }

    // Link the activities in a loop so last->next == first
    kb_screen_act.activity = act_info.first_activity;
    gui_chain_activities(&kb_screen_act, &act_info);

    *activity_ptr = act_info.first_activity;
}
