#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

#define NUM_KEYBOARD_ROWS 3

static void make_mnemonic_screen(
    gui_activity_t** activity_ptr, const char* title, const char* msg, btn_data_t* btns, const size_t num_btns)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(title);
    JADE_ASSERT(msg);
    JADE_ASSERT(btns);

    gui_make_activity(activity_ptr);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 68, 32);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, message
    gui_view_node_t* text_status;
    gui_make_text(&text_status, msg, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, buttons
    add_buttons(vsplit, UI_ROW, btns, num_btns);
}

void make_mnemonic_welcome_screen(gui_activity_t** activity_ptr)
{
    // First btn looks like '<-'
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MNEMONIC_EXIT },
        { .txt = "New", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC },
        { .txt = "Recover", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RECOVER_MNEMONIC } };
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!",
        "Do you want to create a new\nwallet, or recover an existing\nwallet?", btns, 3);

    // Set the intially selected item to the 'New' button
    gui_set_activity_initial_selection(*activity_ptr, btns[1].btn);
}

void make_new_mnemonic_screen(gui_activity_t** activity_ptr)
{
    btn_data_t btns[] = { { .txt = "12 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC_12_BEGIN },
        { .txt = "Advanced", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC_ADVANCED } };
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!",
        "A new recovery phrase will be\ngenerated.\nWrite these words down and\nstore them somewhere safe.", btns, 2);
}

void make_new_mnemonic_screen_advanced(gui_activity_t** activity_ptr)
{
    btn_data_t btns[] = { { .txt = "12 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC_12_BEGIN },
        { .txt = "24 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC_24_BEGIN } };
    make_mnemonic_screen(activity_ptr, "Welcome to Jade!", "\nSelect recovery phrase length.", btns, 2);
}

void make_mnemonic_recovery_screen(gui_activity_t** activity_ptr, const bool temporary_restore)
{
    btn_data_t btns[] = { { .txt = "12 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RECOVER_MNEMONIC_12_BEGIN },
        { .txt = "Advanced", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RECOVER_MNEMONIC_ADVANCED } };

    // If temporary-restore, change the default from '12 words' to 'Scan QR'
    if (temporary_restore) {
        btns[0].txt = "Scan QR";
        btns[0].ev_id = BTN_RECOVER_MNEMONIC_QR_BEGIN;
    }

    make_mnemonic_screen(activity_ptr, "Welcome to Jade!", "\nHow would you like to\nrecover the wallet?", btns, 2);
}

void make_mnemonic_recovery_screen_advanced(gui_activity_t** activity_ptr)
{
    btn_data_t btns[] = { { .txt = "12 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RECOVER_MNEMONIC_12_BEGIN },
        { .txt = "24 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RECOVER_MNEMONIC_24_BEGIN },
        { .txt = "Scan QR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RECOVER_MNEMONIC_QR_BEGIN } };
    make_mnemonic_screen(
        activity_ptr, "Welcome to Jade!", "\nSelect recovery phrase length\nor to scan a QR code.", btns, 3);
}

void make_bip85_mnemonic_screen(gui_activity_t** activity_ptr)
{
    btn_data_t btns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BIP85_EXIT },
        { .txt = "12 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BIP85_12_WORDS },
        { .txt = "24 words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BIP85_24_WORDS } };
    make_mnemonic_screen(activity_ptr, "BIP85",
        "\nCreate a new recovery phrase\nderived from the current wallet\nand selected index number.", btns, 3);
}

static void make_show_new_mnemonic_page(link_activity_t* page_act, const size_t nwords, const size_t first_index,
    char* word1, char* word2, char* word3, char* word4)
{
    JADE_ASSERT(page_act);
    JADE_ASSERT(word1);
    JADE_ASSERT(word2);
    JADE_ASSERT(word3);
    JADE_ASSERT(word4);

    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(first_index < nwords);
    JADE_ASSERT(first_index % 4 == 0);

    const bool first_page = first_index == 0;
    const bool last_page = first_index == nwords - 4;

    gui_activity_t* act = NULL;
    gui_make_activity(&act);

    // Display 4 words per page, in a column
    // NOTE: the words prefixed by their index, eg. "1: river"
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 0);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* btn_back = NULL;
    gui_view_node_t* btn_next = NULL;

    // First three rows are just the words (in a central column)
    // Final row also has the back/fwd buttons
    char prefixed_word[16];
    char* words[] = { word1, word2, word3, word4 };
    for (int irow = 0; irow < 4; ++irow) {
        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 25, 50, 25);
        gui_set_parent(hsplit, vsplit);

        // Padding/back-button - first page is 'exit', otherwise 'previous page'
        if (irow == 3) {
            gui_make_button(&btn_back, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN,
                first_page ? BTN_MNEMONIC_EXIT : BTN_MNEMONIC_PREV, NULL);
            gui_set_margins(btn_back, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn_back, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn_back, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn_back, hsplit);

            gui_view_node_t* text;
            gui_make_text_font(&text, "=", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
            gui_set_parent(text, btn_back);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        } else {
            gui_view_node_t* filler;
            gui_make_fill(&filler, TFT_BLACK);
            gui_set_parent(filler, hsplit);
        }

        // index-prefixed word, eg. "1: river"
        const int ret = snprintf(prefixed_word, sizeof(prefixed_word), "%2u: %s", first_index + irow + 1, words[irow]);
        JADE_ASSERT(ret > 0 && ret < sizeof(prefixed_word));
        gui_view_node_t* text_word;
        gui_make_text_font(&text_word, prefixed_word, TFT_WHITE, UBUNTU16_FONT);
        gui_set_text_noise(text_word, TFT_BLACK);
        gui_set_padding(text_word, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 12);
        gui_set_align(text_word, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(text_word, hsplit);

        // Padding/fwd-button - last page is 'verify', otherwise 'next page'
        if (irow == 3) {
            gui_make_button(&btn_next, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN,
                last_page ? BTN_MNEMONIC_VERIFY : BTN_MNEMONIC_NEXT, NULL);
            gui_set_margins(btn_next, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn_next, TFT_BLACK, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn_next, TFT_BLOCKSTREAM_GREEN);
            gui_set_parent(btn_next, hsplit);

            gui_view_node_t* text;
            if (last_page) {
                gui_make_text_font(&text, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
            } else {
                gui_make_text_font(&text, ">", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
            }
            gui_set_parent(text, btn_next);
            gui_set_align(text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        } else {
            gui_view_node_t* filler;
            gui_make_fill(&filler, TFT_BLACK);
            gui_set_parent(filler, hsplit);
        }
    }
    JADE_ASSERT(btn_back);
    JADE_ASSERT(btn_next);

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(act, btn_next);

    // Copy activity and prev and next buttons into output struct
    page_act->activity = act;
    page_act->prev_button = first_page ? NULL : btn_back;
    page_act->next_button = last_page ? NULL : btn_next;
}

void make_show_mnemonic(
    gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[], const size_t nwords)
{
    JADE_ASSERT(first_activity_ptr);
    JADE_ASSERT(last_activity_ptr);
    JADE_ASSERT(words);

    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);

    // Chain the legal screen activities
    link_activity_t page_act = {};
    linked_activities_info_t act_info = {};

    const size_t npages = nwords / 4; // 4 words per page
    for (size_t j = 0; j < npages; j++) {
        make_show_new_mnemonic_page(
            &page_act, nwords, j * 4, words[j * 4], words[j * 4 + 1], words[j * 4 + 2], words[j * 4 + 3]);
        gui_chain_activities(&page_act, &act_info);
    }

    *first_activity_ptr = act_info.first_activity;
    *last_activity_ptr = act_info.last_activity;
}

static void make_confirm_mnemonic_page(
    gui_activity_t** activity_ptr, gui_view_node_t** text_box, size_t confirm_index, char* word_prev, char* word_next)
{
    JADE_ASSERT(activity_ptr);
    JADE_INIT_OUT_PPTR(text_box);

    JADE_LOGD("Confirm page index %u, prev %s, next %s", confirm_index, word_prev, word_next);

    gui_make_activity(activity_ptr);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
    gui_make_text_font(&text_left, "=", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
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
    gui_make_text_font(&text_right, ">", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
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
    JADE_ASSERT(confirm > 0 && confirm < nwords - 1); // Must be able to access next and previous entries
    make_confirm_mnemonic_page(activity_ptr, text_box_ptr, confirm, words[confirm - 1], words[confirm + 1]);
}

void make_enter_wordlist_word_page(gui_activity_t** activity_ptr, const char* title, const bool show_enter_btn,
    gui_view_node_t** textbox, gui_view_node_t** backspace, gui_view_node_t** enter, gui_view_node_t** keys,
    const size_t keys_len)
{
    // title is optional
    JADE_ASSERT(activity_ptr);
    JADE_INIT_OUT_PPTR(textbox);
    JADE_INIT_OUT_PPTR(backspace);
    JADE_INIT_OUT_PPTR(enter);
    JADE_ASSERT(keys);
    JADE_ASSERT(keys_len == 26); // ie. A->Z

    gui_make_activity(activity_ptr);
    (*activity_ptr)->selectables_wrap = true; // allow the button cursor to wrap

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

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
            size_t font = DEFAULT_FONT;
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
            gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, btn_ev_id, NULL);
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
                if (show_enter_btn) {
                    lines[l][c] = 'S';
                    font = VARIOUS_SYMBOLS_FONT; // 'S' becomes <tick>
                }
                *enter = btn;
            }

            gui_view_node_t* label;
            const char str[2] = { lines[l][c], 0 };
            gui_make_text_font(&label, str, TFT_WHITE, font);
            gui_set_parent(label, btn);
            gui_set_align(label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        }
    }
}

void make_select_word_page(gui_activity_t** activity_ptr, const char* title, const char* initial_label,
    gui_view_node_t** textbox, gui_view_node_t** label)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(title);
    JADE_ASSERT(initial_label);
    JADE_INIT_OUT_PPTR(textbox);
    JADE_INIT_OUT_PPTR(label);

    gui_make_activity(activity_ptr);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 45, 25, 30);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, label
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* text_label;
    gui_make_text(&text_label, initial_label, TFT_WHITE);
    gui_set_parent(text_label, text_bg);
    gui_set_padding(text_label, GUI_MARGIN_TWO_VALUES, 1, 0);
    gui_set_align(text_label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    *label = text_label;

    // second row, words
    gui_view_node_t* words_hsplit;
    gui_make_hsplit(&words_hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(words_hsplit, GUI_MARGIN_TWO_VALUES, 0, 4);
    gui_set_parent(words_hsplit, vsplit);

    gui_view_node_t* text_left;
    gui_make_text_font(&text_left, "=", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
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
    gui_make_text_font(&text_right, ">", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(text_right, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(text_right, words_hsplit);
}

void make_calculate_final_word_page(gui_activity_t** activity_ptr)
{
    btn_data_t btns[] = { { .txt = "Existing", .font = GUI_DEFAULT_FONT, .ev_id = BTN_MNEMONIC_FINAL_WORD_EXISTING },
        { .txt = "Calculate", .font = GUI_DEFAULT_FONT, .ev_id = BTN_MNEMONIC_FINAL_WORD_CALCULATE } };
    make_mnemonic_screen(activity_ptr, "Final Word",
        "Enter final word from existing\nrecovery phrase or calculate\nvalid ones?", btns, 2);
}

void make_using_passphrase_screen(
    gui_activity_t** activity_ptr, const bool use_passphrase_once, const bool use_passphrase_always)
{
    JADE_ASSERT(!(use_passphrase_once && use_passphrase_always));

    gui_make_activity(activity_ptr);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 34, 34, 32);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, question
    gui_view_node_t* txt_question;
    gui_make_text(&txt_question, "Do you want to login with a\nBIP39 passphrase?", TFT_WHITE);
    gui_set_parent(txt_question, vsplit);
    gui_set_padding(txt_question, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 4);
    gui_set_align(txt_question, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // Second row, warning
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 15, 85);
    gui_set_parent(hsplit, vsplit);

    gui_view_node_t* hazard_symbol;
    gui_make_text_font(&hazard_symbol, "G", TFT_YELLOW, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(hazard_symbol, hsplit);
    gui_set_padding(hazard_symbol, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 0);
    gui_set_align(hazard_symbol, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    gui_view_node_t* txt_warning;
    gui_make_text(&txt_warning, "A lost passphrase will lead\nto a loss of funds!", TFT_WHITE);
    gui_set_parent(txt_warning, hsplit);
    gui_set_align(txt_warning, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // third row, buttons
    btn_data_t btns[] = { { .txt = "No", .font = GUI_DEFAULT_FONT, .ev_id = BTN_USE_PASSPHRASE_NO },
        { .txt = "Always", .font = GUI_DEFAULT_FONT, .ev_id = BTN_USE_PASSPHRASE_ALWAYS },
        { .txt = "Once", .font = GUI_DEFAULT_FONT, .ev_id = BTN_USE_PASSPHRASE_ONCE } };
    add_buttons(vsplit, UI_ROW, btns, 3);

    // Set default button
    gui_view_node_t* default_btn = use_passphrase_once ? btns[1].btn
        : use_passphrase_always                        ? btns[2].btn
                                                       : btns[0].btn;
    gui_set_activity_initial_selection(*activity_ptr, default_btn);
}

// confrm passphrase - note we use UBUNTU16_FONT to ensure all punctuation characters are
// displayed as expected (no font glyphs have been overridden/changed in this font)
void make_confirm_passphrase_screen(gui_activity_t** activity_ptr, const char* passphrase, gui_view_node_t** textbox)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(passphrase);
    JADE_INIT_OUT_PPTR(textbox);

    gui_make_activity(activity_ptr);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 40, 27, 33);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    // first row, message
    gui_view_node_t* text;
    gui_make_text(&text, "Do you confirm the following\npassphrase:", TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_ALL_DIFFERENT, 8, 4, 0, 0);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // second row, passphrase
    gui_view_node_t* entered_phrase;
    gui_make_text_font(&entered_phrase, passphrase, TFT_WHITE, UBUNTU16_FONT);
    gui_set_text_noise(entered_phrase, TFT_BLACK);
    gui_set_parent(entered_phrase, vsplit);
    gui_set_padding(entered_phrase, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_text_scroll(entered_phrase, TFT_BLACK);
    gui_set_align(entered_phrase, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);
    *textbox = entered_phrase;

    // third row, Yes and No buttons
    btn_data_t btns[] = { { .txt = "No", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO },
        { .txt = "Yes", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES } };
    add_buttons(vsplit, UI_ROW, btns, 2);
}

void make_confirm_qr_export_activity(gui_activity_t** activity_ptr)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(vsplit, (*activity_ptr)->root_node);

    gui_view_node_t* text;
    gui_make_text(&text, "\nDraw the CompactSeedQR for\nuse with Recovery Phrase\nLogin.", TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 6, 4);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // third row, Yes and No buttons
    btn_data_t btns[] = { { .txt = "Skip", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO },
        { .txt = "Next", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES } };
    add_buttons(vsplit, UI_ROW, btns, 2);

    // Select 'Next' button by default
    gui_set_activity_initial_selection(*activity_ptr, btns[1].btn);
}

void make_export_qr_overview_activity(gui_activity_t** activity_ptr, const Icon* icon)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(icon);

    gui_make_activity(activity_ptr);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, (*activity_ptr)->root_node);

    // lhs - text
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 54, 30);
    gui_set_parent(vsplit, hsplit);

    // rhs - icon
    gui_view_node_t* icon_bg;
    gui_make_fill(&icon_bg, TFT_DARKGREY);
    gui_set_parent(icon_bg, hsplit);

    gui_view_node_t* qr_icon_node;
    gui_make_icon(&qr_icon_node, icon, TFT_BLACK, &TFT_LIGHTGREY);
    gui_set_align(qr_icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(qr_icon_node, icon_bg);

    // first row, header
    gui_view_node_t* title;
    gui_make_text(&title, "QR Export", TFT_WHITE);
    gui_set_parent(title, vsplit);
    gui_set_align(title, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(title, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    // second row, message
    gui_view_node_t* text;
    gui_make_text(&text, "\nCompactSeedQR\n     Overview", TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 8, 1);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // Just a 'begin' button
    btn_data_t btn = { .txt = "Begin", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_EXPORT_BEGIN };
    add_buttons(vsplit, UI_COLUMN, &btn, 1);
}

void make_export_qr_fragment_activity(
    gui_activity_t** activity_ptr, const Icon* icon, gui_view_node_t** icon_node, gui_view_node_t** label_node)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(icon);
    JADE_INIT_OUT_PPTR(icon_node);
    JADE_INIT_OUT_PPTR(label_node);

    gui_make_activity(activity_ptr);

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, (*activity_ptr)->root_node);

    // lhs - text
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 16, 38, 18, 28);
    gui_set_parent(vsplit, hsplit);

    // rhs - icon
    gui_view_node_t* icon_bg;
    gui_make_fill(&icon_bg, TFT_DARKGREY);
    gui_set_parent(icon_bg, hsplit);

    gui_view_node_t* qr_icon_node;
    gui_make_icon(&qr_icon_node, icon, TFT_BLACK, &TFT_LIGHTGREY);
    gui_set_align(qr_icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(qr_icon_node, icon_bg);
    *icon_node = qr_icon_node;

    // first row, header
    gui_view_node_t* title;
    gui_make_text(&title, "Draw QR", TFT_WHITE);
    gui_set_parent(title, vsplit);
    gui_set_align(title, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(title, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    // second row, message - tweaked for hw revision
#if defined(CONFIG_BOARD_TYPE_JADE)
    const char* msg = "Scroll through\nQR using the\nwheel";
#elif defined(CONFIG_BOARD_TYPE_JADE_V1_1)
    const char* msg = "Scroll through\nQR using the\njog-wheel";
#else
    const char* msg = "Scroll through\nQR using left &\nright buttons";
#endif
    gui_view_node_t* text;
    gui_make_text(&text, msg, TFT_WHITE);
    gui_set_parent(text, vsplit);
    gui_set_padding(text, GUI_MARGIN_TWO_VALUES, 6, 4);
    gui_set_align(text, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // third row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* icon_label;
    gui_make_text(&icon_label, "", TFT_WHITE);
    gui_set_parent(icon_label, text_bg);
    gui_set_align(icon_label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    *label_node = icon_label;

    // Just a 'done' button
    btn_data_t btn = { .txt = "Done", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_EXPORT_DONE };
    add_buttons(vsplit, UI_COLUMN, &btn, 1);
}
