#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

#define NUM_KEYBOARD_ROWS 3

gui_activity_t* make_mnemonic_setup_type_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MNEMONIC_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "Begin Setup", .font = GUI_DEFAULT_FONT, .ev_id = BTN_MNEMONIC_METHOD },
        { .txt = "Advanced Setup", .font = GUI_DEFAULT_FONT, .ev_id = BTN_MNEMONIC_ADVANCED } };

    gui_activity_t* const act = make_menu_activity("Setup Type", hdrbtns, 2, menubtns, 2);

    // Set the intially selected item to the 'New' button
    gui_set_activity_initial_selection(act, menubtns[0].btn);

    return act;
}

gui_activity_t* make_mnemonic_setup_method_activity(const bool advanced)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MNEMONIC_TYPE },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    // In advanced mode offer 12/14 word new-mnemonics.
    // Go straight to 12-word new-mnemonic setup in basic case.
    btn_data_t menubtns[] = { { .txt = "Create New Wallet",
                                  .font = GUI_DEFAULT_FONT,
                                  .ev_id = advanced ? BTN_NEW_MNEMONIC : BTN_NEW_MNEMONIC_12 },
        { .txt = "Restore Wallet", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RESTORE_MNEMONIC } };

    gui_activity_t* const act
        = make_menu_activity(advanced ? "Advanced Setup" : "Setup Method", hdrbtns, 2, menubtns, 2);

    // Set the intially selected item to the 'New' button
    gui_set_activity_initial_selection(act, menubtns[0].btn);

    return act;
}

gui_activity_t* make_new_mnemonic_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_MNEMONIC_METHOD },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "12 Words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC_12 },
        { .txt = "24 Words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NEW_MNEMONIC_24 } };

    gui_activity_t* const act = make_menu_activity("Recovery Phrase", hdrbtns, 2, menubtns, 2);

    // Set the intially selected item to the '12 words' button
    gui_set_activity_initial_selection(act, menubtns[0].btn);

    return act;
}

gui_activity_t* make_restore_mnemonic_activity(const bool temporary_restore)
{
    // If temporary restore this is the root so 'back' becomes 'exit'
    btn_data_t hdrbtns[] = { { .txt = "=",
                                 .font = JADE_SYMBOLS_16x16_FONT,
                                 .ev_id = temporary_restore ? BTN_MNEMONIC_EXIT : BTN_MNEMONIC_METHOD },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "12 Words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RESTORE_MNEMONIC_12 },
        { .txt = "24 Words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RESTORE_MNEMONIC_24 },
        { .txt = "Scan QR", .font = GUI_DEFAULT_FONT, .ev_id = BTN_RESTORE_MNEMONIC_QR } };

#ifdef CONFIG_HAS_CAMERA
    const size_t nbtns = 3;
    const size_t selected = temporary_restore ? 2 : 0;
#else
    const size_t nbtns = 2;
    const size_t selected = 0;
#endif

    gui_activity_t* const act = make_menu_activity("Restore Wallet", hdrbtns, 2, menubtns, nbtns);

    // Set the intially selected item to the '12 words' or 'Scan QR' buttons
    gui_set_activity_initial_selection(act, menubtns[selected].btn);

    return act;
}

gui_activity_t* make_bip85_mnemonic_words_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BIP85_EXIT },
        { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    btn_data_t menubtns[] = { { .txt = "12 Words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BIP85_12_WORDS },
        { .txt = "24 Words", .font = GUI_DEFAULT_FONT, .ev_id = BTN_BIP85_24_WORDS } };

    gui_activity_t* const act = make_menu_activity("BIP85", hdrbtns, 2, menubtns, 2);

    // Set the intially selected item to the '12 words' button
    gui_set_activity_initial_selection(act, menubtns[0].btn);

    return act;
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

    const uint32_t prev_ev_id = first_page ? BTN_MNEMONIC_EXIT : BTN_MNEMONIC_PREV;
    const uint32_t next_ev_id = last_page ? BTN_MNEMONIC_VERIFY : BTN_MNEMONIC_NEXT;
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = prev_ev_id },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = next_ev_id } };

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(act, "Recovery Phrase", hdrbtns, 2, NULL);

    // Rows are the index-prefixed words in a single column
    // Display 4 words per page, in a column
    // NOTE: the words prefixed by their index, eg. "1: river"
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 4, 12, 14, 32);
    gui_set_parent(vsplit, parent);

    char prefixed_word[16];
    char* words[] = { word1, word2, word3, word4 };
    for (int irow = 0; irow < 4; ++irow) {
        // index-prefixed word, eg. "1:  river"
        const int ret = snprintf(prefixed_word, sizeof(prefixed_word), "%2u:  %s", first_index + irow + 1, words[irow]);
        JADE_ASSERT(ret > 0 && ret < sizeof(prefixed_word));
        gui_view_node_t* word;
        gui_make_text(&word, prefixed_word, TFT_WHITE);
        gui_set_text_noise(word, TFT_BLACK);
        gui_set_align(word, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(word, vsplit);
    }

    // Set the intially selected item to the next/verify (ie. the last) button
    gui_set_activity_initial_selection(act, hdrbtns[1].btn);

    // Copy activity and prev and next buttons into output struct
    page_act->activity = act;
    page_act->prev_button = first_page ? NULL : hdrbtns[0].btn;
    page_act->next_button = last_page ? NULL : hdrbtns[1].btn;
}

void make_show_mnemonic_activities(
    gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[], const size_t nwords)
{
    JADE_INIT_OUT_PPTR(first_activity_ptr);
    JADE_INIT_OUT_PPTR(last_activity_ptr);
    JADE_ASSERT(words);

    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);

    // Chain the screen activities
    link_activity_t page_act = {};
    linked_activities_info_t act_info = {};

    const size_t npages = nwords / 4; // 4 words per page
    for (size_t j = 0; j < npages; ++j) {
        make_show_new_mnemonic_page(
            &page_act, nwords, j * 4, words[j * 4], words[j * 4 + 1], words[j * 4 + 2], words[j * 4 + 3]);
        gui_chain_activities(&page_act, &act_info);
    }

    *first_activity_ptr = act_info.first_activity;
    *last_activity_ptr = act_info.last_activity;
}

gui_activity_t* make_confirm_mnemonic_word_activity(
    gui_view_node_t** text_box, const size_t idxconfirm, char* words[], const size_t nwords)
{
    JADE_INIT_OUT_PPTR(text_box);
    JADE_ASSERT(idxconfirm > 0 && idxconfirm < nwords - 1); // Must be able to access next and previous entries
    JADE_ASSERT(words);

    const char* const prev_word = words[idxconfirm - 1];
    const char* const next_word = words[idxconfirm + 1];

    JADE_LOGD("Confirm page index %u, prev %s, next %s", idxconfirm, prev_word, next_word);

    // First row, title/hint index (1-based index)
    char str[32];
    int ret = snprintf(str, sizeof(str), "Confirm word %u", idxconfirm + 1);
    JADE_ASSERT(ret > 0 && ret < sizeof(str));

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(act, str, NULL, 0, NULL);

    // Then prior word, word to select, following word
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 30, 40, 30);
    gui_set_parent(vsplit, parent);
    gui_view_node_t* hsplit;
    gui_view_node_t* node;

    // second row, previous word
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 30, 40, 30);
    gui_set_parent(hsplit, vsplit);

    ret = snprintf(str, sizeof(str), "%u", idxconfirm);
    JADE_ASSERT(ret > 0 && ret < sizeof(str));

    gui_make_text(&node, str, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 0, 10, 0, 0);
    gui_set_parent(node, hsplit);

    gui_make_text(&node, prev_word, TFT_WHITE);
    gui_set_text_noise(node, TFT_BLACK);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // third row, selection word
    gui_make_fill(&node, gui_get_highlight_color());
    gui_set_margins(node, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 4);
    gui_set_parent(node, vsplit);

    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 25, 50, 25);
    gui_set_parent(hsplit, node);

    gui_make_text_font(&node, "H", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // This text will be updated, so we add a background that will
    // be repainted every time to wipe the previous string
    gui_make_fill(&node, gui_get_highlight_color());
    gui_set_parent(node, hsplit);

    gui_make_text(text_box, "", TFT_WHITE);
    gui_set_text_noise(*text_box, gui_get_highlight_color());
    gui_set_align(*text_box, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*text_box, node);

    gui_make_text_font(&node, "I", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // fourth row, following word
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 30, 40, 30);
    gui_set_parent(hsplit, vsplit);

    ret = snprintf(str, sizeof(str), "%u", idxconfirm + 2);
    JADE_ASSERT(ret > 0 && ret < sizeof(str));

    gui_make_text(&node, str, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 0, 10, 0, 0);
    gui_set_parent(node, hsplit);

    gui_make_text(&node, next_word, TFT_WHITE);
    gui_set_text_noise(node, TFT_BLACK);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    return act;
}

gui_activity_t* make_enter_wordlist_word_activity(gui_view_node_t** titletext, const bool show_enter_btn,
    gui_view_node_t** textbox, gui_view_node_t** backspace, gui_view_node_t** enter, gui_view_node_t** keys,
    const size_t keys_len)
{
    JADE_INIT_OUT_PPTR(titletext);
    JADE_INIT_OUT_PPTR(textbox);
    JADE_INIT_OUT_PPTR(backspace);
    JADE_INIT_OUT_PPTR(enter);
    JADE_ASSERT(keys);
    JADE_ASSERT(keys_len == 26); // ie. A->Z

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* parent = add_title_bar(act, "", NULL, 0, titletext);
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, parent);

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
            size_t font = UBUNTU16_FONT;
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
            gui_make_button(&btn, TFT_BLACK, gui_get_highlight_color(), btn_ev_id, NULL);
            gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
            gui_set_borders(btn, TFT_BLUE, 1, GUI_BORDER_ALL);
            gui_set_borders_selected_color(btn, gui_get_highlight_color());
            gui_set_borders_inactive_color(btn, TFT_BLACK);
            gui_set_parent(btn, hsplit);

            if (lines[l][c] >= 'A' && lines[l][c] <= 'Z') {
                const size_t index = lines[l][c] - 'A';
                JADE_ASSERT(index < keys_len);
                keys[index] = btn;
            } else if (lines[l][c] == '|') {
                font = DEFAULT_FONT; // '|' becomes <backspace>
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

    return act;
}

gui_activity_t* make_calculate_final_word_activity(void)
{
    btn_data_t hdrbtns[] = { { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
        { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_MNEMONIC_FINAL_WORD_HELP } };

    btn_data_t ftrbtns[] = { { .txt = "Existing",
                                 .font = GUI_DEFAULT_FONT,
                                 .ev_id = BTN_MNEMONIC_FINAL_WORD_EXISTING,
                                 .borders = GUI_BORDER_TOPRIGHT },
        { .txt = "Calculate",
            .font = GUI_DEFAULT_FONT,
            .ev_id = BTN_MNEMONIC_FINAL_WORD_CALCULATE,
            .borders = GUI_BORDER_TOPLEFT } };

    gui_activity_t* const act
        = make_show_message_activity("   Enter existing word\n    or display possible\n           options?", 12,
            "Final Word", hdrbtns, 2, ftrbtns, 2);

    // Select 'Existing' button by default
    gui_set_activity_initial_selection(act, ftrbtns[0].btn);

    return act;
}

gui_activity_t* make_confirm_passphrase_activity(const char* passphrase, gui_view_node_t** textbox)
{
    JADE_ASSERT(passphrase);
    JADE_INIT_OUT_PPTR(textbox);

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, "Confirm Passphrase", NULL, 0, NULL);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(vsplit, parent);

    // passphrase
    gui_make_text(textbox, passphrase, TFT_WHITE);
    gui_set_text_noise(*textbox, TFT_BLACK);
    gui_set_parent(*textbox, vsplit);

    gui_set_padding(*textbox, GUI_MARGIN_ALL_DIFFERENT, 12, 2, 0, 4);
    gui_set_align(*textbox, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // third row, Yes and No buttons
    btn_data_t ftrbtns[] = { { .txt = "No", .font = GUI_DEFAULT_FONT, .ev_id = BTN_NO, .borders = GUI_BORDER_TOPRIGHT },
        { .txt = "Yes", .font = GUI_DEFAULT_FONT, .ev_id = BTN_YES, .borders = GUI_BORDER_TOPLEFT } };
    add_buttons(vsplit, UI_ROW, ftrbtns, 2);

    return act;
}

gui_activity_t* make_export_qr_overview_activity(const Icon* icon, const bool initial)
{
    JADE_ASSERT(icon);

    gui_activity_t* const act = gui_make_activity();

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, act->root_node);

    // lhs - text
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 55, 25);
    gui_set_parent(vsplit, hsplit);

    // rhs - icon
    gui_view_node_t* icon_bg;
    gui_make_fill(&icon_bg, TFT_DARKGREY);
    gui_set_parent(icon_bg, hsplit);

    gui_view_node_t* node;
    gui_make_icon(&node, icon, TFT_BLACK, &TFT_LIGHTGREY);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, icon_bg);

    // First row, header, just a back button initally, a back and next button if looping round
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_EXPORT_PREV, .borders = GUI_BORDER_ALL },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE }, // spacer
              { .txt = NULL, .font = JADE_SYMBOLS_16x16_FONT, .ev_id = GUI_BUTTON_EVENT_NONE } };

    if (!initial) {
        hdrbtns[2].txt = ">";
        hdrbtns[2].ev_id = BTN_QR_EXPORT_NEXT;
        hdrbtns[2].borders = GUI_BORDER_ALL;
    }

    add_buttons(vsplit, UI_ROW, hdrbtns, 3);

    // Second row, message
    const char* msg = initial ? "     Draw\n   SeedQR" : " SeedQR on\n  template";
    gui_make_text(&node, msg, TFT_WHITE);
    gui_set_parent(node, vsplit);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 16, 0, 0, 0);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    btn_data_t ftrbtn
        = { .txt = "Start", .font = GUI_DEFAULT_FONT, .ev_id = BTN_QR_EXPORT_NEXT, .borders = GUI_BORDER_TOP };
    if (!initial) {
        // Just a 'Start' button
        ftrbtn.txt = "Done";
        ftrbtn.ev_id = BTN_QR_EXPORT_DONE;
    }
    add_buttons(vsplit, UI_ROW, &ftrbtn, 1);

    // Select 'Start'/Done button by default
    gui_set_activity_initial_selection(act, ftrbtn.btn);

    return act;
}

gui_activity_t* make_export_qr_fragment_activity(
    const Icon* icon, gui_view_node_t** icon_node, gui_view_node_t** label_node)
{
    JADE_ASSERT(icon);
    JADE_INIT_OUT_PPTR(icon_node);
    JADE_INIT_OUT_PPTR(label_node);

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* node;

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(hsplit, act->root_node);

    // lhs - text
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 20, 60);
    gui_set_parent(vsplit, hsplit);

    // rhs - icon
    gui_make_fill(&node, TFT_DARKGREY);
    gui_set_parent(node, hsplit);

    gui_make_icon(icon_node, icon, TFT_BLACK, &TFT_LIGHTGREY);
    gui_set_align(*icon_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*icon_node, node);

    // First row, header, just back and forward buttons
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_EXPORT_PREV, .borders = GUI_BORDER_ALL },
              { .txt = NULL, .font = GUI_DEFAULT_FONT, .ev_id = GUI_BUTTON_EVENT_NONE },
              { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_QR_EXPORT_NEXT, .borders = GUI_BORDER_ALL } };
    add_buttons(vsplit, UI_ROW, hdrbtns, 3);

    // Second row, grid ref
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, vsplit);

    gui_make_text(label_node, "", TFT_WHITE);
    gui_set_align(*label_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*label_node, node);

    // third row, message
    gui_make_text(&node, "     Draw\n SeedQR on\n  template", TFT_WHITE);
    gui_set_parent(node, vsplit);
    gui_set_padding(node, GUI_MARGIN_TWO_VALUES, 4, 0);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    // Select 'Next' button by default
    gui_set_activity_initial_selection(act, hdrbtns[2].btn);

    return act;
}
