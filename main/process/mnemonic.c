#include <string.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include "../button_events.h"
#include "../camera.h"
#include "../gui.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../random.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"

#include "process_utils.h"

#include <sodium/utils.h>

#define NUM_RANDOM_WORDS 8
#define NUM_WORDS_CONFIRM 6
#define MNEMONIC_BUFLEN 256 // Should be large enough for all mnemonics
#define MNEMONIC_MIN_LENGTH 95 // 24 * 3 (shortest words) + 23 (spaces)

// main/ui/mnemonic.c
void make_mnemonic_welcome_screen(gui_activity_t** activity_ptr);
void make_mnemonic_recovery_screen(gui_activity_t** activity_ptr);
void make_show_mnemonic(gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[24]);
void make_confirm_mnemonic_screen(
    gui_activity_t** activity_ptr, gui_view_node_t** text_box_ptr, size_t confirm, char* words[24]);
void make_recover_word_page(gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** backspace,
    gui_view_node_t** enter, gui_view_node_t** keys);
void make_recover_word_page_select10(
    gui_activity_t** activity_ptr, gui_view_node_t** textbox, gui_view_node_t** status);
void make_mnemonic_qr_scan(gui_activity_t** activity_ptr, gui_view_node_t** camera_node, gui_view_node_t** textbox);

// Pinserver interaction
bool pinclient_savekeys(
    jade_process_t* process, const uint8_t* pin, size_t pin_size, const struct keychain_handle* khandle);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
// Function to change the mnemonic word separator and provide pointers to
// the start of the words.  USed when confirming one word at a time.
static void change_mnemonic_word_separator(
    char* mnemonic, const size_t len, const char old_separator, const char new_separator, char* words[24])
{
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(words);

    size_t word = 0, i = 0;
    for (/*nothing*/; i < len && word < 24; ++i, ++word) {
        words[word] = mnemonic + i; // Pointer to the start of each word
        for (/*nothing*/; i < len; ++i) {
            if (mnemonic[i] == old_separator) {
                mnemonic[i] = new_separator;
                break;
            }
        }
    }
    JADE_ASSERT(word == 24);
    JADE_ASSERT(i == len + 1);
}

static bool mnemonic_new(jade_process_t* process, char mnemonic[MNEMONIC_BUFLEN])
{
    JADE_ASSERT(process);

    // generate and show the mnemonic
    char* new_mnemonic = NULL;
    keychain_get_new_mnemonic(&new_mnemonic);
    JADE_ASSERT(new_mnemonic);
    const size_t mnemonic_len = strnlen(new_mnemonic, MNEMONIC_BUFLEN);
    SENSITIVE_PUSH(new_mnemonic, mnemonic_len);
    JADE_ASSERT(mnemonic_len < MNEMONIC_BUFLEN); // buffer should be large enough for any mnemonic

    // Some fixed mnemonics for testing purposes
    // char *new_mnemonic = strdup("fish inner face ginger orchard permit useful method fence kidney chuckle party
    // favorite sunset draw limb science crane oval letter slot invite sadness banana");     // common test mnemonic
    // char *new_mnemonic = strdup("vast half sort lounge odor arrow coast butter tag tail matter social march crane
    // artwork agent need beach wedding actress unlock fitness leisure hurt");             // another valid one char
    // *new_mnemonic = strdup("clump money embrace choose river crime sense donate document alter enforce script field
    // place chase bitter clutch hundred thumb churn money order member squirrel"); // invalid mnemonic
    // JADE_LOGD("new mnemonic = %s", new_mnemonic);

    // Copy into output buffer
    strcpy(mnemonic, new_mnemonic);

    // Change the word separator to a null so we can treat each word as a terminated string.
    char* words[24];
    SENSITIVE_PUSH(words, sizeof(words));
    change_mnemonic_word_separator(new_mnemonic, mnemonic_len, ' ', '\0', words);
    bool mnemonic_confirmed = false;

    // create the "show mnemonic" only once and then reuse it
    gui_activity_t* first_activity = NULL;
    gui_activity_t* last_activity = NULL;

    make_show_mnemonic(
        &first_activity, &last_activity, words); // TODO: zero the GUI memory where the mnemonic is stored

    while (!mnemonic_confirmed) {
        gui_set_current_activity(first_activity);
        gui_activity_wait_event(last_activity, GUI_BUTTON_EVENT, BTN_MNEMONIC_NEXT, NULL, NULL, NULL, 0);

        JADE_LOGD("moving on to confirm_mnemonic");

        bool already_confirmed[24] = { false };

        // confirm the mnemonic
        for (size_t i = 0; i < NUM_WORDS_CONFIRM; i++) {
            gui_activity_t* confirm_act;
            gui_view_node_t* textbox;

            size_t selected;
            do {
                selected = 1 + get_uniform_random_byte(22); // never select the first or last word
            } while (already_confirmed[selected]);
            already_confirmed[selected] = true;

            make_confirm_mnemonic_screen(&confirm_act, &textbox, selected, words);
            JADE_LOGD("selected = %u", selected);
            gui_set_current_activity(confirm_act);

            bool already_picked[24] = { false };
            already_picked[selected] = true;
            already_picked[selected - 1] = true;
            already_picked[selected + 1] = true;

            size_t random_words[NUM_RANDOM_WORDS] = { 0 };
            random_words[0] = selected;

            for (size_t j = 1; j < NUM_RANDOM_WORDS; j++) {
                size_t new_word;
                do {
                    new_word = get_uniform_random_byte(24);
                } while (already_picked[new_word]);

                already_picked[new_word] = true;
                random_words[j] = new_word;
            }

            uint8_t index = get_uniform_random_byte(NUM_RANDOM_WORDS);
            gui_update_text(textbox, words[random_words[index]]); // set the first word

            bool stop = false;
            int32_t ev_id = ESP_EVENT_ANY_ID;
            while (!stop) {
                // wait for a GUI event
                gui_activity_wait_event(confirm_act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

                switch (ev_id) {
                case GUI_WHEEL_LEFT_EVENT:
                    index = (index + 1) % NUM_RANDOM_WORDS;
                    gui_update_text(textbox, words[random_words[index]]);
                    break;

                case GUI_WHEEL_RIGHT_EVENT:
                    // Avoid unsigned wrapping below zero
                    index = (index + NUM_RANDOM_WORDS - 1) % NUM_RANDOM_WORDS;
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
            } else if (i == NUM_WORDS_CONFIRM - 1) { // last word, and it's correct
                mnemonic_confirmed = true;
                break;
            }
        }
    }
    JADE_LOGD("mnemonic confirmed");
    SENSITIVE_POP(words);
    SENSITIVE_POP(new_mnemonic);
    wally_free_string(new_mnemonic);
    return true;
}

static size_t enable_relevant_chars(char* word, struct words* wordlist, gui_activity_t* act, gui_view_node_t* backspace,
    gui_view_node_t** btns, bool* valid_word)
{
    JADE_ASSERT(word);
    JADE_ASSERT(wordlist);
    JADE_ASSERT(act);
    JADE_ASSERT(backspace);
    JADE_ASSERT(btns);
    JADE_ASSERT(valid_word);

    const size_t word_len = strlen(word);
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
        const uint8_t initial = get_uniform_random_byte(26);
        gui_set_active(act, btns[initial], true);
        gui_select_node(act, btns[initial]);

        // Then enable all the (other) buttons
        for (size_t i = 0; i < 26; i++) {
            gui_set_active(act, btns[i], true);
        }

        return 0;
    }

    size_t num_possible_words = 0;

    *valid_word = false;

    bool enabled[26] = { false };
    for (size_t wordlist_index = 0; wordlist_index < 2048; wordlist_index++) {
        char* wordlist_extracted = NULL; // TODO: check strlen(wordlist_extracted)
        bip39_get_word(wordlist, wordlist_index, &wordlist_extracted);

        const int32_t res = strncmp(wordlist_extracted, word, word_len);
        if (res < 0) {
            wally_free_string(wordlist_extracted);
            continue;
        } else if (res > 0) {
            wally_free_string(wordlist_extracted);
            break;
        }

        // compare the entire word now, not just the prefix
        if (strcmp(word, wordlist_extracted) == 0) {
            *valid_word = true;
        }

        num_possible_words++;

        size_t char_index = wordlist_extracted[word_len] - 'a';
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

    for (size_t i = 0; i < 26; ++i) {
        gui_set_active(act, btns[i], enabled[i]);

        if (selectNext && enabled[i]) {
            gui_select_node(act, btns[i]);
            selectNext = false;
        }
    }

    return num_possible_words;
}

static size_t valid_words(char* word, struct words* wordlist, size_t* possible_word_list,
    const size_t possible_word_list_len, bool* valid_word)
{
    JADE_ASSERT(word);
    JADE_ASSERT(wordlist);
    JADE_ASSERT(possible_word_list);
    JADE_ASSERT(valid_word);

    const size_t word_len = strlen(word);
    JADE_LOGD("word = %s, word_len = %u", word, word_len);

    size_t num_possible_words = 0;
    for (size_t i = 0; i < possible_word_list_len; i++) {
        possible_word_list[i] = 0;
    }
    *valid_word = false;

    for (size_t wordlist_index = 0; wordlist_index < 2048; wordlist_index++) {
        char* wordlist_extracted = NULL; // TODO: check strlen(wordlist_extracted)
        bip39_get_word(wordlist, wordlist_index, &wordlist_extracted);

        const int32_t res = strncmp(wordlist_extracted, word, word_len);

        if (res < 0) {
            wally_free_string(wordlist_extracted);
            continue;
        } else if (res > 0) {
            wally_free_string(wordlist_extracted);
            break;
        }

        // compare the entire word now, not just the prefix
        if (strcmp(word, wordlist_extracted) == 0) {
            *valid_word = true;
        }

        // return first possible_word_list_len compatible words
        if (num_possible_words < possible_word_list_len) {
            possible_word_list[num_possible_words] = wordlist_index;
        }

        num_possible_words++;

        wally_free_string(wordlist_extracted);
    }

    return num_possible_words;
}

static bool mnemonic_recover(jade_process_t* process, char mnemonic[MNEMONIC_BUFLEN])
{
    struct words* wordlist;
    bip39_get_wordlist(NULL, &wordlist);
    size_t mnemonic_offset = 0;

    gui_view_node_t* btns[26];
    gui_view_node_t *textbox = NULL, *backspace = NULL, *enter = NULL;
    gui_activity_t* enter_word_activity = NULL;
    make_recover_word_page(&enter_word_activity, &textbox, &backspace, &enter, btns);

    gui_view_node_t* textbox_list = NULL;
    gui_view_node_t* status = NULL;
    gui_activity_t* choose_word_activity = NULL;
    make_recover_word_page_select10(&choose_word_activity, &textbox_list, &status);

    for (int word_index = 0; word_index < 24; ++word_index) {
        char word[16] = { 0 };
        bool valid_word = false;
        size_t char_index = 0;
        int32_t ev_id;

        // Reset display for next word
        gui_set_current_activity(enter_word_activity);
        enable_relevant_chars(word, wordlist, enter_word_activity, backspace, btns, &valid_word);
        gui_update_text(textbox, word);
        enter->is_active = false;

        char enter_word_title[16];
        const int ret = snprintf(enter_word_title, sizeof(enter_word_title), "Insert word %u", word_index + 1);
        JADE_ASSERT(ret > 0 && ret < sizeof(enter_word_title));
        gui_set_title(enter_word_title);

        while (char_index < 16) {
            valid_word = false;
            size_t possible_word_list[10];
            size_t possible_words = valid_words(word, wordlist, possible_word_list, 10, &valid_word);
            if (possible_words < 11) {
                gui_set_current_activity(choose_word_activity);
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
                bip39_get_word(wordlist, possible_word_list[selected], &wordlist_extracted);
                gui_update_text(textbox_list, wordlist_extracted);
                wally_free_string(wordlist_extracted);
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

                    if (selected == possible_words) { // delete
                        gui_update_text(textbox_list, "|");
                    } else {
                        char* wordlist_extracted = NULL;
                        bip39_get_word(wordlist, possible_word_list[selected], &wordlist_extracted);
                        gui_update_text(textbox_list, wordlist_extracted);
                        wally_free_string(wordlist_extracted);
                    }
                } // while stop

                if (selected < possible_words) { // ie. a word was chosen
                    char* wordlist_extracted = NULL;
                    bip39_get_word(wordlist, possible_word_list[selected], &wordlist_extracted);
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

                gui_set_current_activity(enter_word_activity);
                enable_relevant_chars(word, wordlist, enter_word_activity, backspace, btns, &valid_word);
                gui_update_text(textbox, word);
                gui_set_title(enter_word_title);

            } else { // else if possible_words >= 11
                gui_activity_wait_event(enter_word_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

                if (ev_id >= BTN_KEYBOARD_A && ev_id <= BTN_KEYBOARD_Z) {
                    word[char_index++] = 'a' + ev_id - BTN_KEYBOARD_A;
                } else if (ev_id == BTN_KEYBOARD_BACKSPACE) {
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
                }

                enable_relevant_chars(word, wordlist, enter_word_activity, backspace, btns, &valid_word);
                gui_update_text(textbox, word);

                if (ev_id == BTN_KEYBOARD_BACKSPACE && char_index > 0) {
                    gui_select_node(enter_word_activity, backspace);
                }
            }
        } // cycle on characters
    } // cycle on words

    return true;
}

static bool mnemonic_qr(jade_process_t* process, char mnemonic[MNEMONIC_BUFLEN])
{
    gui_activity_t* activity;
    jade_camera_data_t camera_data;
    SENSITIVE_PUSH(&camera_data, sizeof(jade_camera_data_t));

    make_mnemonic_qr_scan(&activity, &camera_data.camera, &camera_data.text);
    gui_set_current_activity(activity);
    camera_data.activity = activity;
    camera_data.qr_seen = false;
    camera_data.strdata[0] = '\0';
    camera_data.event_data = NULL;
    camera_data.image_buffer = NULL;

    TaskHandle_t camera_task;
    const BaseType_t retval
        = xTaskCreatePinnedToCore(&jade_camera_task, "jade_camera", 64 * 1024, &camera_data, 5, &camera_task, 1);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create jade_camera task, xTaskCreatePinnedToCore() returned %d", retval);

    int32_t ev_id = 0;
    gui_activity_wait_event(activity, JADE_EVENT, CAMERA_EXIT, NULL, &ev_id, NULL, 0);

    vTaskDelete(camera_task);
    jade_camera_stop();

    // If we scanned a qr-code, return any string payload as a potential mnemonic
    const bool scanned_qr = camera_data.qr_seen;
    if (scanned_qr) {
        // Check the amount of data in the camera-structure fits in the mnemonic buffer.
        // If not, set to emtpty string, as not a valid mnemonic in either case.
        const size_t len = strnlen(camera_data.strdata, sizeof(camera_data.strdata));
        JADE_ASSERT(len < sizeof(camera_data.strdata));

        if (len < MNEMONIC_BUFLEN) {
            strcpy(mnemonic, camera_data.strdata);
        } else {
            JADE_LOGW("String data from qr unexpectedly long - ignored: %u", len);
            mnemonic[0] = '\0';
        }
    }

    cleanup_camera_data(&camera_data);
    SENSITIVE_POP(&camera_data);
    return scanned_qr;
}
#endif // CONFIG_DEBUG_UNATTENDED_CI

void mnemonic_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    JADE_ASSERT(!keychain_has_pin());

    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "auth_user");
    char mnemonic[MNEMONIC_BUFLEN]; // buffer should be large enough for any mnemonic
    SENSITIVE_PUSH(mnemonic, sizeof(mnemonic));

    // free any existing global keychain (not that one should exist at this point)
    free_keychain();
    struct keychain_handle khandle;
    SENSITIVE_PUSH(&khandle, sizeof(khandle));

    // welcome screen
    // TODO: maybe split the screen in two parts: new or recover -> recover_mnemonic, recover_qr
    gui_activity_t* activity;
    make_mnemonic_welcome_screen(&activity);

    bool got_mnemonic = false;
    while (!got_mnemonic) {
        gui_set_current_activity(activity);

// In a debug unattended ci build, use hardcoded mnemonic after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        int32_t ev_id;
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
        JADE_ASSERT(ret);

        switch (ev_id) {
        case BTN_RECOVER_MNEMONIC:
            make_mnemonic_recovery_screen(&activity);
            break;

        case BTN_RECOVER_MNEMONIC_BEGIN:
            got_mnemonic = mnemonic_recover(process, mnemonic);
            break;

        case BTN_QR_MNEMONIC_BEGIN:
            got_mnemonic = mnemonic_qr(process, mnemonic);
            break;

        case BTN_NEW_MNEMONIC_BEGIN:
        default:
            got_mnemonic = mnemonic_new(process, mnemonic);
        }
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        strcpy(mnemonic,
            "fish inner face ginger orchard permit useful method fence kidney chuckle party favorite sunset draw limb "
            "science crane oval letter slot invite sadness banana");
        got_mnemonic = true;
#endif

        if (got_mnemonic) {
            display_message_activity("Processing...");

            // If the mnemonic is valid, derive temporary keychain from it
            got_mnemonic = keychain_derive(mnemonic, &khandle);
            if (!got_mnemonic) {
                JADE_LOGW("Invalid mnemonic");
                await_error_activity("Invalid mnemonic");
            }
        }
    }

    // The mnemonic is covered by 'sensitive' - but even so we can zero it here
    // to blank it out as soon as possible.  The subsequent bzero is harmless.
    wally_bzero(mnemonic, sizeof(mnemonic));

    // Enter PIN to lock mnemonic/key material.
    // In a debug unattended ci build, use hardcoded pin after a short delay
    pin_insert_activity_t* pin_insert;
    make_pin_insert_activity(&pin_insert, "Enter New PIN", "New PIN:");
    JADE_ASSERT(pin_insert);
    jade_process_free_on_exit(process, pin_insert);
    SENSITIVE_PUSH(pin_insert, sizeof(pin_insert_activity_t));

    uint8_t pin[sizeof(pin_insert->pin)];
    SENSITIVE_PUSH(pin, sizeof(pin));

    while (true) {
        gui_set_title("Enter New PIN");
        gui_set_current_activity(pin_insert->activity);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        run_pin_entry_loop(pin_insert);
#else
        const uint8_t testpin[sizeof(pin_insert->pin)] = { 0, 1, 2, 3, 4, 5 };

        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        memcpy(pin_insert->pin, testpin, sizeof(testpin));
#endif

        // this is the first pin, copy it and clear screen fields
        memcpy(pin, pin_insert->pin, sizeof(pin));
        clear_current_pin(pin_insert);

        // have user confirm it
        gui_set_title("Confirm New PIN");
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        run_pin_entry_loop(pin_insert);
#else
        vTaskDelay(CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        memcpy(pin_insert->pin, testpin, sizeof(testpin));
#endif

        // check that the two pins are the same
        JADE_LOGD("Checking pins match");
        if (!sodium_memcmp(pin, pin_insert->pin, sizeof(pin))) {
            // Pins match
            JADE_LOGI("New pin confirmed");
            break;
        } else {
            // Pins mismatch - try again
            await_error_activity("Pin mismatch, please try again");
            clear_current_pin(pin_insert);
        }
    }

    display_message_activity("Persisting PIN data...");

    // Ok, have keychain and a PIN - do the pinserver 'setpin' process
    // (This should persist the mnemonic keys encrypted in the flash)
    if (pinclient_savekeys(process, pin, sizeof(pin), &khandle)) {
        set_keychain(&khandle);
        JADE_LOGI("Success");
    } else {
        JADE_LOGW("Set-Pin / persist keys failed.");
        await_error_activity("Failed to persist key data");
    }

    // Clear out pin and temporary keychain and mnemonic
    SENSITIVE_POP(pin);
    SENSITIVE_POP(pin_insert);
    SENSITIVE_POP(&khandle);
    SENSITIVE_POP(mnemonic);
}
