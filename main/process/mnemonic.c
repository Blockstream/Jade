#include <wally_bip39.h>

#include "../button_events.h"
#include "../camera.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../random.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"

#include "process_utils.h"

#include <ctype.h>

// NOTE: Jade only supports the bip39 English wordlist

// Should be large enough for all 12 and 24 word mnemonics
#define MNEMONIC_MAXWORDS 24
#define MNEMONIC_BUFLEN 256

#define PASSPHRASE_MAX_DISPLAY_LEN 16

// main/ui/mnemonic.c
void make_mnemonic_welcome_screen(gui_activity_t** activity_ptr);
void make_new_mnemonic_screen(gui_activity_t** activity_ptr);
void make_new_mnemonic_screen_advanced(gui_activity_t** activity_ptr);
void make_mnemonic_recovery_screen(gui_activity_t** activity_ptr);
void make_mnemonic_recovery_screen_advanced(gui_activity_t** activity_ptr);
void make_show_mnemonic(
    gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[], size_t nwords);
void make_confirm_mnemonic_screen(
    gui_activity_t** activity_ptr, gui_view_node_t** text_box_ptr, size_t confirm, char* words[], size_t nwords);
void make_recover_word_page(gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** backspace,
    gui_view_node_t** enter, gui_view_node_t** keys, size_t keys_len);
void make_recover_word_page_select10(
    gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** status);
void make_using_passphrase_screen(gui_activity_t** activity_ptr, const bool offer_always_option);
void make_confirm_passphrase_screen(gui_activity_t** activity_ptr, const char* passphrase, gui_view_node_t** textbox);

// Function to change the mnemonic word separator and provide pointers to
// the start of the words.  USed when confirming one word at a time.
static void change_mnemonic_word_separator(char* mnemonic, const size_t len, const char old_separator,
    const char new_separator, char* words[], const size_t nwords)
{
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(words);

    size_t word = 0, i = 0;
    for (/*nothing*/; i < len && word < nwords; ++i, ++word) {
        words[word] = mnemonic + i; // Pointer to the start of each word
        for (/*nothing*/; i < len; ++i) {
            if (mnemonic[i] == old_separator) {
                mnemonic[i] = new_separator;
                break;
            }
        }
    }
    JADE_ASSERT(word == nwords);
    JADE_ASSERT(i == len + 1);
}

static bool mnemonic_new(const size_t nwords, char* mnemonic, const size_t mnemonic_len)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(mnemonic_len == MNEMONIC_BUFLEN);

    // Generate and show the mnemonic - NOTE: only the English wordlist is supported.
    char* new_mnemonic = NULL;
    keychain_get_new_mnemonic(&new_mnemonic, nwords);
    JADE_ASSERT(new_mnemonic);
    const size_t new_mnemonic_len = strnlen(new_mnemonic, MNEMONIC_BUFLEN);
    JADE_ASSERT(new_mnemonic_len < MNEMONIC_BUFLEN); // buffer should be large enough for any mnemonic
    SENSITIVE_PUSH(new_mnemonic, new_mnemonic_len);

    // Copy into output buffer
    strcpy(mnemonic, new_mnemonic);

    // Change the word separator to a null so we can treat each word as a terminated string.
    // Large enough for 12 and 24 word mnemonic
    char* words[MNEMONIC_MAXWORDS];
    SENSITIVE_PUSH(words, sizeof(words));
    change_mnemonic_word_separator(new_mnemonic, new_mnemonic_len, ' ', '\0', words, nwords);
    bool mnemonic_confirmed = false;

    // create the "show mnemonic" only once and then reuse it
    gui_activity_t* first_activity = NULL;
    gui_activity_t* last_activity = NULL;
    make_show_mnemonic(&first_activity, &last_activity, words, nwords);
    JADE_ASSERT(first_activity);
    JADE_ASSERT(last_activity);

    while (!mnemonic_confirmed) {
        gui_set_current_activity(first_activity);

        esp_event_handler_instance_t ctx;
        wait_event_data_t* wait_data = make_wait_event_data();
        esp_event_handler_instance_register(
            GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, wait_data, &ctx);
        int32_t ev_id;
        while (true) {
            ev_id = ESP_EVENT_ANY_ID;
            if (sync_wait_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, wait_data, NULL, &ev_id, NULL, 0) != ESP_OK) {
                continue;
            }
            if (ev_id == BTN_MNEMONIC_EXIT) {
                // User abandonded
                JADE_LOGD("user abandoned noting mnemonic");
                esp_event_handler_instance_unregister(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, ctx);
                free_wait_event_data(wait_data);
                goto cleanup;
            }
            if (ev_id == BTN_MNEMONIC_VERIFY) {
                // User ready to verify mnemonic
                JADE_LOGD("moving on to confirm mnemonic");
                esp_event_handler_instance_unregister(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, ctx);
                free_wait_event_data(wait_data);
                break;
            }
        }

        // Large enough for 12 and 24 word mnemonic
        bool already_confirmed[MNEMONIC_MAXWORDS] = { false };

        // Confirm the mnemonic - the number of words to confirm
        // and the number of options presented for each word.
        const size_t num_words_confirm = nwords == MNEMONIC_MAXWORDS ? 6 : 4;
        const size_t num_words_options = nwords == MNEMONIC_MAXWORDS ? 8 : 6;
        for (size_t i = 0; i < num_words_confirm; ++i) {
            size_t selected;
            do {
                selected = 1 + get_uniform_random_byte(nwords - 2); // never select the first or last word
            } while (already_confirmed[selected]);
            already_confirmed[selected] = true;

            gui_activity_t* confirm_act = NULL;
            gui_view_node_t* textbox = NULL;
            make_confirm_mnemonic_screen(&confirm_act, &textbox, selected, words, nwords);
            JADE_ASSERT(confirm_act);
            JADE_LOGD("selected = %u", selected);

            // Large enough for 12 and 24 word mnemonic
            bool already_picked[MNEMONIC_MAXWORDS] = { false };
            already_picked[selected] = true;
            already_picked[selected - 1] = true;
            already_picked[selected + 1] = true;

            // Large enough for 12 and 24 word mnemonic
            // (Only really needs to be as big as 'num_words_options' so MAXWORDS is plenty)
            size_t random_words[MNEMONIC_MAXWORDS] = { 0 };
            random_words[0] = selected;

            for (size_t j = 1; j < num_words_options; ++j) {
                size_t new_word;
                do {
                    new_word = get_uniform_random_byte(nwords);
                } while (already_picked[new_word]);

                already_picked[new_word] = true;
                random_words[j] = new_word;
            }

            uint8_t index = get_uniform_random_byte(num_words_options);
            gui_update_text(textbox, words[random_words[index]]); // set the first word

            gui_set_current_activity(confirm_act);

            bool stop = false;
            while (!stop) {
                // wait for a GUI event
                ev_id = ESP_EVENT_ANY_ID;
                gui_activity_wait_event(confirm_act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

                switch (ev_id) {
                case GUI_WHEEL_LEFT_EVENT:
                    index = (index + 1) % num_words_options;
                    gui_update_text(textbox, words[random_words[index]]);
                    break;

                case GUI_WHEEL_RIGHT_EVENT:
                    // Avoid unsigned wrapping below zero
                    index = (index + num_words_options - 1) % num_words_options;
                    gui_update_text(textbox, words[random_words[index]]);
                    break;

                default:
                    // Stop the loop on a 'click' event
                    stop = (ev_id == gui_get_click_event());
                    break;
                }
            }

            JADE_LOGD("selected word at index %u", index);

            // the wrong word has been selected
            if (random_words[index] != selected) {
                await_error_activity("Wrong, please try again");
                mnemonic_confirmed = false;
                break;
            } else if (i == num_words_confirm - 1) { // last word, and it's correct
                mnemonic_confirmed = true;
                break;
            }
        }
    }

    JADE_ASSERT(mnemonic_confirmed);
    JADE_LOGD("mnemonic confirmed");

cleanup:
    SENSITIVE_POP(words);
    SENSITIVE_POP(new_mnemonic);
    wally_free_string(new_mnemonic);
    return mnemonic_confirmed;
}

// NOTE: only the English wordlist is supported.
static void enable_relevant_chars(const char* word, const size_t word_len, gui_activity_t* act,
    gui_view_node_t* backspace, gui_view_node_t** btns, const size_t btns_len)
{
    JADE_ASSERT(word);
    JADE_ASSERT(act);
    JADE_ASSERT(backspace);
    JADE_ASSERT(btns);
    JADE_ASSERT(btns_len == 26); // ie A->Z

    JADE_LOGD("word = %s, word_len = %u", word, word_len);

    // Enable backspace in all cases
    gui_set_active(act, backspace, true);

    // TODO: are there any invalid characters to start the word?

    // No characters currently selected (ie. no word stem)
    if (word_len == 0) {
        // NOTE: Doing the below in this order appears to reduce drawing flicker.
        // If we enable all buttons first, the previously selected button is drawn enabled
        // and selected, then the selection switches to the new/randomly-chosen item.
        // This can look a bit messy - so we activate and select the new button first,
        // then enable the rest.

        // First select a character button at random
        const uint8_t initial = get_uniform_random_byte(btns_len);
        gui_set_active(act, btns[initial], true);
        gui_select_node(act, btns[initial]);

        // Then enable all the (other) buttons
        for (size_t i = 0; i < btns_len; ++i) {
            gui_set_active(act, btns[i], true);
        }

        return;
    }

    bool enabled[26] = { false };
    for (size_t wordlist_index = 0; wordlist_index < 2048; ++wordlist_index) {
        char* wordlist_extracted = NULL; // TODO: check strlen(wordlist_extracted)
        JADE_WALLY_VERIFY(bip39_get_word(NULL, wordlist_index, &wordlist_extracted));

        const int32_t res = strncmp(wordlist_extracted, word, word_len);
        if (res < 0) {
            wally_free_string(wordlist_extracted);
            continue;
        } else if (res > 0) {
            wally_free_string(wordlist_extracted);
            break;
        }

        const size_t char_index = wordlist_extracted[word_len] - 'a';
        enabled[char_index] = true;

        wally_free_string(wordlist_extracted);
    }

    // As above, first mark the new selected item as active and selected,
    // and then go through the other letters marking them as active (or not).
    // NOTE: Doing this appears to reduce drawing flicker around selected item.
    bool selectNext = true;
    const size_t inserted_char_index = word[word_len - 1] - 'a';
    if (enabled[inserted_char_index]) {
        gui_set_active(act, btns[inserted_char_index], true);
        gui_select_node(act, btns[inserted_char_index]);
        selectNext = false;
    }

    for (size_t i = 0; i < btns_len; ++i) {
        gui_set_active(act, btns[i], enabled[i]);

        if (selectNext && enabled[i]) {
            gui_select_node(act, btns[i]);
            selectNext = false;
        }
    }
}

// NOTE: only the English wordlist is supported.
static size_t valid_words(const char* word, const size_t word_len, size_t* possible_word_list,
    const size_t possible_word_list_len, bool* exact_match)
{
    JADE_ASSERT(word);
    JADE_ASSERT(possible_word_list);
    JADE_ASSERT(possible_word_list_len);
    JADE_ASSERT(exact_match);

    JADE_LOGD("word = %s, word_len = %u", word, word_len);

    *exact_match = false;
    size_t num_possible_words = 0;
    for (size_t i = 0; i < possible_word_list_len; ++i) {
        possible_word_list[i] = 0;
    }

    for (size_t wordlist_index = 0; wordlist_index < 2048; ++wordlist_index) {
        char* wordlist_extracted = NULL; // TODO: check strlen(wordlist_extracted)
        JADE_WALLY_VERIFY(bip39_get_word(NULL, wordlist_index, &wordlist_extracted));

        // Test if passed 'word' is a valid prefix of the wordlist word
        const int32_t res = strncmp(wordlist_extracted, word, word_len);

        if (res < 0) {
            // No there yet, continue to next work
            wally_free_string(wordlist_extracted);
            continue;
        } else if (res > 0) {
            // Too late - gone past word - may as well abandon
            wally_free_string(wordlist_extracted);
            break;
        }

        // If prefix matches, see if it is an exact match for the entire word
        // (ie. word lengths are also same)
        if (wordlist_extracted[word_len] == '\0') {
            JADE_ASSERT(!num_possible_words); // should only happen on first match ...
            JADE_ASSERT(!*exact_match); // and so should only happen at most once!
            *exact_match = true;
        }

        // Return first possible_word_list_len compatible words
        if (num_possible_words < possible_word_list_len) {
            possible_word_list[num_possible_words] = wordlist_index;
        }

        ++num_possible_words;

        wally_free_string(wordlist_extracted);
    }

    return num_possible_words;
}

static bool mnemonic_recover(const size_t nwords, char* mnemonic, const size_t mnemonic_len)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(mnemonic_len == MNEMONIC_BUFLEN);

    // NOTE: only the English wordlist is supported.
    size_t mnemonic_offset = 0;

    gui_view_node_t* btns[26] = {};
    const size_t btns_len = sizeof(btns) / sizeof(btns[0]);
    gui_view_node_t *textbox = NULL, *backspace = NULL, *enter = NULL;
    gui_activity_t* enter_word_activity = NULL;
    make_recover_word_page(&enter_word_activity, &textbox, &backspace, &enter, btns, btns_len);
    JADE_ASSERT(enter_word_activity);

    gui_view_node_t* textbox_list = NULL;
    gui_view_node_t* status = NULL;
    gui_activity_t* choose_word_activity = NULL;
    make_recover_word_page_select10(&choose_word_activity, &textbox_list, &status);
    JADE_ASSERT(choose_word_activity);

    for (size_t word_index = 0; word_index < nwords; ++word_index) {
        char word[16] = { 0 };
        size_t char_index = 0;
        int32_t ev_id;

        // Reset display for next word
        char enter_word_title[16];
        const int ret = snprintf(enter_word_title, sizeof(enter_word_title), "Insert word %u", word_index + 1);
        JADE_ASSERT(ret > 0 && ret < sizeof(enter_word_title));
        gui_set_activity_title(enter_word_activity, enter_word_title);
        gui_set_current_activity(enter_word_activity);
        enter->is_active = false;

        while (char_index < 16) {
            bool exact_match = false;
            size_t possible_word_list[10];
            const size_t possible_words = valid_words(word, char_index, possible_word_list, 10, &exact_match);
            if (possible_words < 11) {
                enter->is_active = false;
                char choose_word_title[16];
                const int ret
                    = snprintf(choose_word_title, sizeof(choose_word_title), "Select word %u", word_index + 1);
                JADE_ASSERT(ret > 0 && ret < sizeof(choose_word_title));
                gui_update_text(status, choose_word_title);

                bool stop = false;
                int32_t ev_id = ESP_EVENT_ANY_ID;
                uint8_t selected = 0;
                char* wordlist_extracted = NULL;
                JADE_WALLY_VERIFY(bip39_get_word(NULL, possible_word_list[selected], &wordlist_extracted));
                gui_update_text(textbox_list, wordlist_extracted);
                wally_free_string(wordlist_extracted);

                gui_set_current_activity(choose_word_activity);

                while (!stop) {
                    // wait for a GUI event
                    gui_activity_wait_event(choose_word_activity, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
                    switch (ev_id) {
                    case GUI_WHEEL_LEFT_EVENT:
                        // Avoid unsigned wrapping below zero
                        selected = (selected + (possible_words + 1) - 1) % (possible_words + 1);
                        break;

                    case GUI_WHEEL_RIGHT_EVENT:
                        selected = (selected + 1) % (possible_words + 1);
                        break;

                    default:
                        // Stop the loop on a 'click' event
                        if (ev_id == gui_get_click_event()) {
                            stop = true;
                            break;
                        } else {
                            // Event we're not interested in, loop and await next event.
                            continue;
                        }
                    }

                    if (!stop) {
                        // Selected word was changed
                        if (selected == possible_words) { // delete
                            gui_update_text(textbox_list, "|");
                        } else {
                            char* wordlist_extracted = NULL;
                            JADE_WALLY_VERIFY(bip39_get_word(NULL, possible_word_list[selected], &wordlist_extracted));
                            gui_update_text(textbox_list, wordlist_extracted);
                            wally_free_string(wordlist_extracted);
                        }
                    }
                } // while stop

                if (selected < possible_words) { // ie. a word was chosen
                    char* wordlist_extracted = NULL;
                    JADE_WALLY_VERIFY(bip39_get_word(NULL, possible_word_list[selected], &wordlist_extracted));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
                    strncpy(word, wordlist_extracted, 16);
#pragma GCC diagnostic pop
                    char_index = strlen(wordlist_extracted);
                    wally_free_string(wordlist_extracted);

                    // TODO: maybe check the word one last time?
                    const size_t wordlen = strlen(word);
                    JADE_ASSERT(mnemonic_offset + 1 + wordlen
                        < MNEMONIC_BUFLEN); // buffer should be big enough for any mnemonic
                    if (mnemonic_offset > 0) {
                        mnemonic[mnemonic_offset++] = ' ';
                    }
                    memcpy(mnemonic + mnemonic_offset, word, wordlen);
                    mnemonic_offset += wordlen;
                    mnemonic[mnemonic_offset] = '\0';
                    JADE_LOGD("%s", mnemonic);
                    break; // Exit 'per character' loop, to move to next word / outer loop
                }

                // If we get here it means 'backspace' was pressed
                // Delete last character and go back to keyboard screen
                word[--char_index] = '\0';

                gui_set_activity_title(enter_word_activity, enter_word_title);
                gui_set_current_activity(enter_word_activity);

            } else { // else if possible_words >= 11
                // Update the typed word
                gui_update_text(textbox, word);
                enable_relevant_chars(word, char_index, enter_word_activity, backspace, btns, btns_len);

                gui_activity_wait_event(enter_word_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

                if (ev_id == BTN_KEYBOARD_BACKSPACE) {
                    if (char_index > 0) {
                        // Go back one character
                        word[--char_index] = '\0';
                    } else if (word_index > 0) {
                        // Deleting when no characters entered for this word
                        // Go back to previous word - break out of 'per character' loop,
                        // so we go back round the 'per word' loop, but set the word counter
                        // back two places (so it gets incremented to the previous word).
                        word_index -= 2;
                        break;
                    } else {
                        // Backspace at start of first word - abandon mnemonic entry back to previous screen
                        return false;
                    }
                } else {
                    const char letter_selected = ev_id - BTN_KEYBOARD_ASCII_OFFSET;
                    if (letter_selected >= 'A' && letter_selected <= 'Z') {
                        word[char_index++] = tolower(letter_selected);
                    }
                }

                if (ev_id == BTN_KEYBOARD_BACKSPACE && char_index > 0) {
                    gui_select_node(enter_word_activity, backspace);
                }
            }
        } // cycle on characters
    } // cycle on words

    return true;
}

static bool string_all(const char* s, int (*fntest)(int))
{
    while (*s) {
        if (!fntest(*s++)) {
            return false;
        }
    }
    return true;
}

// Take a nul terminated string of space-separated mnemonic-word prefixes, and populate a string of
// space-separated full mnemonic words (also nul terminated).
// Returns true if it works!  Returns false if any of the prefixes are not a prefix for exactly one
// valid mnemonic word, or if the expanded string is too large for the provided buffer.
// NOTE: There are a load of three-letter words in the bip39 list that are a) valid words in their
// own right, and also b) prefixes to other words.
// eg: bar, barely, bargain, barrel; pen, penalty, pencil; ski, skill, skin, skirt
// In this case we allow/prefer an exact match even when the word is an prefix of other words.
// NOTE: only the English wordlist is supported.
static bool expand_words(const qr_data_t* qr_data, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(buf);
    JADE_ASSERT(buf_len);
    JADE_INIT_OUT_SIZE(written);

    size_t write_pos = 0;
    const char* read_ptr = qr_data->strdata;
    const char* end_ptr = read_ptr;

    // Must be a string of printable characters
    if (!string_all(qr_data->strdata, isprint)) {
        return false;
    }

    while (*end_ptr != '\0' && write_pos < buf_len) {
        // Find the end of this word/prefix
        end_ptr = strchr(read_ptr, ' ');
        if (!end_ptr) {
            // Not found, point to end of string
            end_ptr = qr_data->strdata + qr_data->len;
            JADE_ASSERT(*end_ptr == '\0');
        }
        JADE_ASSERT(end_ptr <= qr_data->strdata + qr_data->len);

        // Lookup prefix in the default (English) wordlist, ensuring exactly one match
        size_t possible_match;
        bool exact_match = false;
        const size_t nmatches = valid_words(read_ptr, (end_ptr - read_ptr), &possible_match, 1, &exact_match);
        if (nmatches != 1 && !exact_match) {
            JADE_LOGW("%d matches for prefix: %.*s", nmatches, (end_ptr - read_ptr), read_ptr);
            return false;
        }

        char* wordlist_extracted = NULL;
        JADE_WALLY_VERIFY(bip39_get_word(NULL, possible_match, &wordlist_extracted));
        const size_t word_len = strlen(wordlist_extracted);
        if (write_pos + word_len >= buf_len) {
            JADE_LOGW("Expanded mnemonic too long");
            wally_free_string(wordlist_extracted);
            return false;
        }

        // Copy the expanded word into the output buffer
        memcpy(buf + write_pos, wordlist_extracted, word_len);
        wally_free_string(wordlist_extracted);
        write_pos += word_len;

        // Copy space separator or nul terminator
        JADE_ASSERT(*end_ptr == ' ' || *end_ptr == '\0');
        buf[write_pos++] = *end_ptr;

        // Update read pointer to be after the whitespace
        read_ptr = end_ptr + 1;
    }

    // Return true if we have successfully consumed all input
    JADE_ASSERT(write_pos <= buf_len);
    *written = write_pos;
    return *end_ptr == '\0';
}

static bool import_seedsigner(const qr_data_t* qr_data, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(buf);
    JADE_ASSERT(buf_len);
    JADE_INIT_OUT_SIZE(written);

    // Must be a string of appropriate length and all digits
    if ((qr_data->len != 48 && qr_data->len != 96) || !string_all(qr_data->strdata, isdigit)) {
        return false;
    }

    // SeedSigner qr support (ie string of word indices).
    // NOTE: only the English wordlist is supported.
    char index_code[5];
    SENSITIVE_PUSH(index_code, sizeof(index_code));
    index_code[4] = '\0';

    size_t write_pos = 0;
    const size_t num_words = qr_data->len == 48 ? 12 : 24;
    for (size_t i = 0; i < num_words; ++i) {
        memcpy(index_code, qr_data->strdata + (i * 4), 4);
        const size_t index = strtol(index_code, NULL, 10);
        if (index > 2047) {
            JADE_LOGE("Error, provided a bip39 word out of range");
            SENSITIVE_POP(index_code);
            return false;
        }

        char* wally_word = NULL;
        JADE_WALLY_VERIFY(bip39_get_word(NULL, index, &wally_word));
        const size_t wordlen = strlen(wally_word);
        if (write_pos + 1 + wordlen + 1 >= buf_len) {
            // Not enough remaining for space, word, nul
            JADE_LOGE("Error, expanded mnemonic string too large for buffer");
            SENSITIVE_POP(index_code);
            return false;
        }

        if (i > 0) {
            // Add space separator
            buf[write_pos++] = ' ';
        }

        // Copy word
        memcpy(buf + write_pos, wally_word, wordlen);
        write_pos += wordlen;
        wally_free_string(wally_word);
    }

    SENSITIVE_POP(index_code);
    buf[write_pos++] = '\0';
    *written = write_pos;
    return true;
}

// Attempt to import mnemonic from supported formats
static bool import_mnemonic(const qr_data_t* qr_data, char* buf, const size_t buf_len, size_t* written)
{
    // 1. Try seedsigner format (string of 4-digit indicies, no spaces)
    // 2. Try to read word prefixes or whole words (space separated)
    // TODO: add bc-ur format?
    return import_seedsigner(qr_data, buf, buf_len, written) || expand_words(qr_data, buf, buf_len, written);
}

// Function to validate qr scanned is (or expands to) a valid mnemonic
// (Passed to the qr-scanner so scanning only stops when this is satisfied)
// NOTE: not 'static' here as also called from debug/test code.
bool import_and_validate_mnemonic(qr_data_t* qr_data)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(qr_data->len < sizeof(qr_data->strdata));
    JADE_ASSERT(qr_data->strdata[qr_data->len] == '\0');

    char buf[sizeof(qr_data->strdata)];
    SENSITIVE_PUSH(buf, sizeof(buf));

    // Try to import mnemonic, validate, and if all good copy over into the qr_data
    size_t written = 0;
    if (import_mnemonic(qr_data, buf, sizeof(buf), &written) && bip39_mnemonic_validate(NULL, buf) == WALLY_OK) {
        JADE_ASSERT(written);
        JADE_ASSERT(written <= sizeof(buf));
        JADE_ASSERT(buf[written - 1] == '\0');

        memcpy(qr_data->strdata, buf, written);
        qr_data->len = written - 1; // Do not include nul-terminator

        SENSITIVE_POP(buf);
        return true;
    }

    // Show the user that a valid qr was scanned, but the string data
    // did not constitute (or expand to) a valid bip39 mnemonic string.
    SENSITIVE_POP(buf);
    await_error_activity("Invalid recovery phrase");
    qr_data->len = 0;
    return false;
}

static bool mnemonic_qr(char* mnemonic, const size_t mnemonic_len)
{
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(mnemonic_len == MNEMONIC_BUFLEN);

    // Pass validation callback above to qr scanner
    qr_data_t qr_data = { .len = 0, .is_valid = import_and_validate_mnemonic };
    SENSITIVE_PUSH(&qr_data, sizeof(qr_data));
    mnemonic[0] = '\0';

    // we return 'true' if we scanned any string data at all
    const bool qr_scanned = jade_camera_scan_qr(&qr_data) && qr_data.len > 0;
    if (!qr_scanned) {
        JADE_LOGW("No qr code scanned");
        goto cleanup;
    }

    if (qr_data.len >= mnemonic_len) {
        JADE_LOGW("String data from qr unexpectedly long - ignored: %u", qr_data.len);
        goto cleanup;
    }

    // Result looks good, copy into mnemonic buffer
    JADE_ASSERT(qr_data.strdata[qr_data.len] == '\0');
    strcpy(mnemonic, qr_data.strdata);

cleanup:
    SENSITIVE_POP(&qr_data);
    return qr_scanned;
}

void get_passphrase(char* passphrase, const size_t passphrase_len, const bool confirm)
{
    JADE_ASSERT(passphrase);
    JADE_ASSERT(passphrase_len);
    passphrase[0] = '\0';

    // We will need this activity later if confirming
    gui_activity_t* confirm_passphrase_activity = NULL;
    gui_view_node_t* text_to_confirm = NULL;
    if (confirm) {
        make_confirm_passphrase_screen(&confirm_passphrase_activity, passphrase, &text_to_confirm);
        JADE_ASSERT(confirm_passphrase_activity);
        JADE_ASSERT(text_to_confirm);
    }

    // For passphrase we want all 4 keyboards
    keyboard_entry_t kb_entry = { .max_allowed_len = passphrase_len - 1 };
    kb_entry.keyboards[0] = KB_LOWER_CASE_CHARS;
    kb_entry.keyboards[1] = KB_UPPER_CASE_CHARS;
    kb_entry.keyboards[2] = KB_NUMBERS_SYMBOLS;
    kb_entry.keyboards[3] = KB_REMAINING_SYMBOLS;
    kb_entry.num_kbs = 4;

    make_keyboard_entry_activity(&kb_entry, "Enter Passphrase");
    JADE_ASSERT(kb_entry.activity);

    bool done = false;
    while (!done) {
        // Run the keyboard entry loop to get a typed passphrase
        run_keyboard_entry_loop(&kb_entry);

        // Perhaps ask user to confirm, before accepting passphrase
        if (confirm) {
            if (kb_entry.len > 0) {
                int32_t ev_id;
                gui_update_text(text_to_confirm, kb_entry.strdata);
                gui_set_current_activity(confirm_passphrase_activity);
                gui_activity_wait_event(
                    confirm_passphrase_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
                done = (ev_id == BTN_YES);
            } else {
                done = await_yesno_activity("Confirm Passphrase", "Do you confirm the empty\npassphrase?", false);
            }
        } else {
            // Not explicitly confirming passphrase, so done
            done = true;
        }
    }

    JADE_ASSERT(kb_entry.len < passphrase_len);
    strcpy(passphrase, kb_entry.strdata);
}

void initialise_with_mnemonic(const bool temporary_restore)
{
    // At this point we should not have any keys in-memory
    JADE_ASSERT(!keychain_get());

    // We only allow setting new keys when encrypted keys are persisted if
    // we are doing a temporary restore.
    JADE_ASSERT(temporary_restore || !keychain_has_pin());

    char mnemonic[MNEMONIC_BUFLEN]; // buffer should be large enough for any mnemonic
    SENSITIVE_PUSH(mnemonic, sizeof(mnemonic));
    keychain_t keydata = { 0 };
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // Initial welcome screen, or straight to 'recovery' screen if doing temporary restore
    gui_activity_t* activity = NULL;
    if (temporary_restore) {
        make_mnemonic_recovery_screen(&activity);
    } else {
        make_mnemonic_welcome_screen(&activity);
    }
    JADE_ASSERT(activity);

    bool got_mnemonic = false;
    bool using_passphrase = false;
    while (!got_mnemonic) {
        gui_set_current_activity(activity);

        // In a debug unattended ci build, use hardcoded mnemonic after a short delay
        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
        JADE_ASSERT(ret);

        switch (ev_id) {
        case BTN_MNEMONIC_EXIT:
            // Abandon setting up mnemonic
            break;

        // Change screens and continue to await button events
        case BTN_NEW_MNEMONIC:
            activity = NULL;
            make_new_mnemonic_screen(&activity);
            JADE_ASSERT(activity);
            continue;

        case BTN_NEW_MNEMONIC_ADVANCED:
            activity = NULL;
            make_new_mnemonic_screen_advanced(&activity);
            JADE_ASSERT(activity);
            using_passphrase = true;
            continue;

        case BTN_RECOVER_MNEMONIC:
            activity = NULL;
            make_mnemonic_recovery_screen(&activity);
            JADE_ASSERT(activity);
            continue;

        case BTN_RECOVER_MNEMONIC_ADVANCED:
            activity = NULL;
            make_mnemonic_recovery_screen_advanced(&activity);
            JADE_ASSERT(activity);
            using_passphrase = true;
            continue;

        // Await user mnemonic entry/confirmation
        case BTN_NEW_MNEMONIC_12_BEGIN:
            got_mnemonic = mnemonic_new(12, mnemonic, sizeof(mnemonic));
            break;

        case BTN_NEW_MNEMONIC_24_BEGIN:
            got_mnemonic = mnemonic_new(24, mnemonic, sizeof(mnemonic));
            break;

        case BTN_RECOVER_MNEMONIC_12_BEGIN:
            got_mnemonic = mnemonic_recover(12, mnemonic, sizeof(mnemonic));
            break;

        case BTN_RECOVER_MNEMONIC_24_BEGIN:
            got_mnemonic = mnemonic_recover(24, mnemonic, sizeof(mnemonic));
            break;

        case BTN_RECOVER_MNEMONIC_QR_BEGIN:
        default:
            got_mnemonic = mnemonic_qr(mnemonic, sizeof(mnemonic));
            break;
        }
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        strcpy(mnemonic,
            "fish inner face ginger orchard permit useful method fence kidney chuckle party favorite sunset draw limb "
            "science crane oval letter slot invite sadness banana");
        got_mnemonic = true;
#endif

        // If we failed to get a mnemonic break/return here
        if (!got_mnemonic) {
            JADE_LOGW("No mnemonic entered");
            break;
        }

        // Check mnemonic valid before entering passphrase
        // NOTE: only the English wordlist is supported.
        if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
            JADE_LOGW("Invalid mnemonic");
            await_error_activity("Invalid recovery phrase");
            break;
        }

        // Perhaps offer/get passphrase (ie. if using advanced options)
        char passphrase[PASSPHRASE_MAX_LEN + 1]; // max chars plus '\0'
        SENSITIVE_PUSH(passphrase, sizeof(passphrase));
        bool always_using_passphrase = false;
        if (using_passphrase) {
            gui_activity_t* act = NULL;
            const bool offer_always_option = !temporary_restore;
            make_using_passphrase_screen(&act, offer_always_option);
            JADE_ASSERT(act);

            gui_set_current_activity(act);

            int32_t ev_id;
            using_passphrase = false;
            if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                if (ev_id == BTN_USE_PASSPHRASE_ALWAYS) {
                    JADE_ASSERT(!temporary_restore);
                    always_using_passphrase = true;
                    using_passphrase = true;
                } else if (ev_id == BTN_USE_PASSPHRASE_ONCE) {
                    using_passphrase = true;
                }
                // Effectively defaults to BTN_USE_PASSPHRASE_NO ie. not using passphrase
            }

            if (using_passphrase) {
                // Ask user to set and confirm the passphrase for this session
                const bool confirm_passphrase = true;
                get_passphrase(passphrase, sizeof(passphrase), confirm_passphrase);
                JADE_ASSERT(strnlen(passphrase, sizeof(passphrase)) < sizeof(passphrase));
            }
        }

        display_message_activity("Processing...");

        // If the mnemonic is valid derive temporary keychain from it.
        // Otherwise break/return here.
        got_mnemonic = keychain_derive_from_mnemonic(mnemonic, using_passphrase ? passphrase : NULL, &keydata);
        SENSITIVE_POP(passphrase);
        if (!got_mnemonic) {
            JADE_LOGW("Failed to derive wallet");
            await_error_activity("Failed to derive wallet");
            break;
        }

        // All good - push temporary into main in-memory keychain
        // and remove the restriction on network-types.
        keychain_set(&keydata, SOURCE_NONE, temporary_restore);
        keychain_clear_network_type_restriction();

        if (!temporary_restore) {
            // We need to cache the root mnemonic entropy as it is this that we will persist
            // encrypted to local flash (requiring a passphrase to derive the wallet master key).
            keychain_cache_mnemonic_entropy(mnemonic);

            // Set persisted wallet 'use passphrase by default' flag
            keychain_set_user_to_enter_passphrase_by_default(always_using_passphrase);
        }
    }

    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(mnemonic);
}
