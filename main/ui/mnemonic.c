#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

static void gen_btns(gui_view_node_t* parent, size_t num_buttons, const char* msgs[], const int32_t ev_ids[],
    gui_view_node_t* out_btns[])
{
    JADE_ASSERT(parent);

    gui_view_node_t* hsplit = NULL;
    switch (num_buttons) {
    case 1:
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 1, 100);
        break;
    case 2:
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
        break;
    case 3:
        gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
        break;
    default:
        return;
    }

    gui_set_parent(hsplit, parent);

    for (size_t i = 0; i < num_buttons; i++) {
        gui_view_node_t* btn1;
        if (ev_ids[i] == GUI_BUTTON_EVENT_NONE) {
            gui_make_fill(&btn1, TFT_BLACK);
        } else {
            gui_make_button(&btn1, TFT_BLACK, ev_ids[i], NULL);
        }
        gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
        gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn1, hsplit);

        if (out_btns) {
            out_btns[i] = btn1;
        }

        gui_view_node_t* textbtn1;
        gui_make_text(&textbtn1, msgs[i], TFT_WHITE);
        gui_set_parent(textbtn1, btn1);
        gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    }
}

/*  Not used atm
   static void make_one_btn_screen(gui_activity_t **activity_ptr, const char *header, const char *msg, const char
   *btn_msg, const int32_t btn_ev_id) { JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, header);
    gui_activity_t *act = *activity_ptr;

    gui_view_node_t *vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 66, 34);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t *text_status;
    gui_make_text(&text_status, msg, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, button
    gen_btns(vsplit, 1, &btn_msg, &btn_ev_id, NULL);
   }
 */
static void make_two_btn_screen(
    gui_activity_t** activity_ptr, const char* header, const char* msg, const char** btn_msg, const int32_t* btn_ev_id)
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
    gen_btns(vsplit, 2, btn_msg, btn_ev_id, NULL);
}

/*  Not used atm
   static void make_three_btn_screen(gui_activity_t **activity_ptr, const char *header, const char *msg, const char
   **btn_msg, const int32_t *btn_ev_id) { JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, header);
    gui_activity_t *act = *activity_ptr;

    gui_view_node_t *vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 66, 34);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t *text_status;
    gui_make_text(&text_status, msg, TFT_WHITE);
    gui_set_parent(text_status, vsplit);
    gui_set_padding(text_status, GUI_MARGIN_TWO_VALUES, 8, 4);
    gui_set_align(text_status, GUI_ALIGN_CENTER, GUI_ALIGN_TOP);

    // second row, button
    gen_btns(vsplit, 3, btn_msg, btn_ev_id, NULL);
   }
 */

void make_mnemonic_welcome_screen(gui_activity_t** activity_ptr)
{
    const char* btn_msg[2];
    btn_msg[0] = "New";
    btn_msg[1] = "Recover";

    int32_t btn_ev_id[2];
    btn_ev_id[0] = BTN_NEW_MNEMONIC_BEGIN;
    btn_ev_id[1] = BTN_RECOVER_MNEMONIC;

    return make_two_btn_screen(activity_ptr, "Welcome to Jade!",
        "A new wallet mnemonic will be\ngenerated.\nWrite these words down and\nstore them somewhere safe", btn_msg,
        btn_ev_id);
}

void make_mnemonic_recovery_screen(gui_activity_t** activity_ptr)
{
    const char* btn_msg[2];
    btn_msg[0] = "Recover";
    btn_msg[1] = "Scan QR";

    int32_t btn_ev_id[2];
    btn_ev_id[0] = BTN_RECOVER_MNEMONIC_BEGIN;
    btn_ev_id[1] = BTN_QR_MNEMONIC_BEGIN;

    return make_two_btn_screen(activity_ptr, "Welcome to Jade!", "Recover the wallet.", btn_msg, btn_ev_id);
}

static void make_mnemonic_page(gui_activity_t** activity_ptr, size_t first_index, char* word1, char* word2, char* word3,
    char* word4, gui_view_node_t* out_btns[])
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(word1);
    JADE_ASSERT(word2);
    JADE_ASSERT(word3);
    JADE_ASSERT(word4);
    JADE_ASSERT(out_btns);

    gui_make_activity(activity_ptr, true, "Mnemonic");
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

    // second row, buttons
    if (first_index == 0) {
        // first page, no prev btn
        gen_btns(vsplit, 2, (const char*[]){ "", "Next" }, (int32_t[]){ GUI_BUTTON_EVENT_NONE, BTN_MNEMONIC_NEXT },
            out_btns);
    } else if (first_index == 24 - 4) {
        // last page, change the label for "next"
        gen_btns(vsplit, 2, (const char*[]){ "Prev", "Verify" }, (int32_t[]){ BTN_MNEMONIC_PREV, BTN_MNEMONIC_NEXT },
            out_btns);
    } else {
        gen_btns(vsplit, 2, (const char*[]){ "Prev", "Next" }, (int32_t[]){ BTN_MNEMONIC_PREV, BTN_MNEMONIC_NEXT },
            out_btns);
    }
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 4, 0, 0, 0);

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(*activity_ptr, out_btns[1]);
}

void make_show_mnemonic(gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[24])
{
    JADE_ASSERT(first_activity_ptr);
    JADE_ASSERT(last_activity_ptr);

    gui_activity_t* prev_act = NULL;
    gui_view_node_t* prev_btn = NULL;
    for (size_t j = 0; j < 6; j++) {
        gui_view_node_t* btns[2];
        gui_activity_t* this = NULL;

        make_mnemonic_page(&this, j * 4, words[j * 4], words[j * 4 + 1], words[j * 4 + 2], words[j * 4 + 3], btns);

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

    gui_make_activity(activity_ptr, true, "Mnemonic check");
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

    // fourth row, followinf word
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

void make_confirm_mnemonic_screen(
    gui_activity_t** activity_ptr, gui_view_node_t** text_box_ptr, size_t confirm, char* words[24])
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(text_box_ptr);

    make_confirm_mnemonic_page(activity_ptr, text_box_ptr, confirm, words[confirm - 1], words[confirm + 1]);
}

// recover
void make_recover_word_page(gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** backspace,
    gui_view_node_t** enter, gui_view_node_t** keys)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(textbox);
    JADE_ASSERT(keys);

    gui_make_activity(activity_ptr, true, "Insert word");
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
    char* lines[3];
    lines[0] = (char[]){ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J' };
    lines[1] = (char[]){ 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S' };
    lines[2] = (char[]){ 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '|' };

    int sizes[] = { 10, 9, 9 };

    int i = 0;
    gui_view_node_t* btns[28];
    for (int l = 0; l < 3; l++) {
        gui_view_node_t* hsplit;
        if (l == 0) {
            gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 10, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24);
        } else if (l == 1) {
            gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 10, 24, 24, 24, 24, 24, 24, 24, 24, 24);
            gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 8);
        } else if (l == 2) {
            gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 9, 24, 24, 24, 24, 24, 24, 24, 24, 24);
            gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 16);
        }

        gui_set_parent(hsplit, vsplit);

        for (int c = 0; c < sizes[l]; c++) {
            size_t btn_ev_id;
            if (lines[l][c] >= 'A' && lines[l][c] <= 'Z') {
                btn_ev_id = lines[l][c] - 'A' + BTN_KEYBOARD_A;
            } else if (lines[l][c] == '|') {
                btn_ev_id = BTN_KEYBOARD_BACKSPACE;
            } else if (lines[l][c] == ' ') {
                btn_ev_id = BTN_KEYBOARD_ENTER;
            } else {
                JADE_ASSERT_MSG(false, "Unknown button pressed %c", lines[l][c]);
            }

            gui_make_button(&btns[i], TFT_BLACK, btn_ev_id, NULL);
            gui_set_margins(btns[i], GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btns[i], TFT_BLUE, 2, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btns[i], TFT_BLOCKSTREAM_GREEN);
            gui_set_borders_inactive_color(btns[i], TFT_BLACK);
            gui_set_parent(btns[i], hsplit);

            if (lines[l][c] >= 'A' && lines[l][c] <= 'Z') {
                keys[lines[l][c] - 'A'] = btns[i];
            } else if (lines[l][c] == '|') {
                *backspace = btns[i];
            } else if (lines[l][c] == ' ') {
                gui_set_borders(btns[i], TFT_DARKGREY, 2, 0);
                *enter = btns[i];
            }

            gui_view_node_t* label;
            char str[2] = { lines[l][c], 0 };
            gui_make_text(&label, str, TFT_WHITE);
            gui_set_parent(label, btns[i]);
            gui_set_align(label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

            i++;
        }
    }
}

void make_recover_word_page_select10(gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** status)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(textbox);

    gui_make_activity(activity_ptr, true, "Recover mnemonic");
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
