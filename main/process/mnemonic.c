#include <wally_bip39.h>

#include "../bcur.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../qrcode.h"
#include "../qrmode.h"
#include "../qrscan.h"
#include "../random.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../utils/util.h"

#include "process_utils.h"

#include <cdecoder.h>
#include <ctype.h>

// NOTE: Jade only supports the bip39 English wordlist

// Should be large enough for all 12 and 24 word mnemonics
#define MNEMONIC_MAXWORDS 24
#define MNEMONIC_BUFLEN 256

#define MAX_NUM_FINAL_WORDS 128
#define NUM_WORDS_SELECT 10

#define WORDLIST_PASSPHRASE_MAX_WORDS 10

#define BIP85_INDEX_MAX 1000000

typedef enum { MNEMONIC_SIMPLE, MNEMONIC_ADVANCED, WORDLIST_PASSPHRASE } wordlist_purpose_t;

// main/ui/mnemonic.c
gui_activity_t* make_mnemonic_setup_type_activity(void);
gui_activity_t* make_mnemonic_setup_method_activity(bool advanced);
gui_activity_t* make_new_mnemonic_activity(void);
gui_activity_t* make_restore_mnemonic_activity(bool temporary_restore);

void make_show_mnemonic_activities(
    gui_activity_t** first_activity_ptr, gui_activity_t** last_activity_ptr, char* words[], size_t nwords);
gui_activity_t* make_confirm_mnemonic_word_activity(gui_view_node_t** text_box_ptr, uint8_t first_word_index,
    uint8_t offset_word_to_confirm, char* words[], size_t nwords);

gui_activity_t* make_enter_wordlist_word_activity(gui_view_node_t** titletext, bool show_enter_btn,
    gui_view_node_t** textbox, gui_view_node_t** backspace, gui_view_node_t** enter, gui_view_node_t** keys,
    size_t keys_len);
gui_activity_t* make_calculate_final_word_activity(void);

gui_activity_t* make_confirm_passphrase_activity(const char* passphrase, gui_view_node_t** textbox);

gui_activity_t* make_export_qr_overview_activity(const Icon* icon, bool initial);
gui_activity_t* make_export_qr_fragment_activity(
    const Icon* icon, gui_view_node_t** icon_node, gui_view_node_t** label_node);

gui_activity_t* make_bip85_mnemonic_words_activity(void);

#ifdef CONFIG_HAS_CAMERA
// Export a mnemonic by asking the user to transcribe it to hard copy, then
// scanning that hard copy back in and verifying the data matches.
// NOTE: the SeedSigner 'CompactSeedQR' format is used (raw entropy).
// NOTE: a 'true' return means the user either completed the QR copy and verification
// process, OR they decided to abandon/skip it - in either case move on to the next step.
// 'false' implies they pressed a 'back' button and we should NOT move forward.
static bool mnemonic_export_qr(const char* mnemonic, bool* export_qr_verified)
{
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(export_qr_verified);

    // Will be set if scan succeeds
    *export_qr_verified = false;

    const char* question[] = { "Draw the", "CompactSeedQR for", "use with QR Mode." };
    if (!await_skipyes_activity(NULL, question, 3, true, "blkstrm.com/seedqr")) {
        // User decided against it at this time - 'true' return implies a definitive
        // decision by the user - as opposed to a simple 'back' button press.
        return true;
    }

    // CompactSeedQR is simply the mnemonic entropy
    // Only 12 or 24 word mnemonics are supported (ie. 128 & 256 bit entropy)
    size_t entropy_len = 0;
    uint8_t entropy[BIP32_ENTROPY_LEN_256]; // Sufficient for 12 and 24 words
    JADE_WALLY_VERIFY(bip39_mnemonic_to_bytes(NULL, mnemonic, entropy, sizeof(entropy), &entropy_len));
    JADE_ASSERT(entropy_len == BIP32_ENTROPY_LEN_128 || entropy_len == BIP32_ENTROPY_LEN_256);

    // Convert the entropy into a small (v1 or v2) qr-code
    QRCode qrcode;
    const uint8_t qrcode_version = entropy_len == BIP32_ENTROPY_LEN_128 ? 1 : 2;
    uint8_t qrbuffer[96]; // underlying qrcode data/work area - opaque
    JADE_ASSERT(sizeof(qrbuffer) > qrcode_getBufferSize(qrcode_version));
    const int qret = qrcode_initBytes(&qrcode, qrbuffer, qrcode_version, ECC_LOW, entropy, entropy_len);
    JADE_ASSERT(qret == 0);

#if CONFIG_DISPLAY_WIDTH >= 480 && CONFIG_DISPLAY_HEIGHT >= 220
    const uint8_t overview_scale = qrcode_version == 1 ? 9 : 8;
    const uint8_t fragment_target_size = 210;
#elif CONFIG_DISPLAY_WIDTH >= 320 && CONFIG_DISPLAY_HEIGHT >= 170
    const uint8_t overview_scale = qrcode_version == 1 ? 7 : 6;
    const uint8_t fragment_target_size = 150;
#else
    const uint8_t overview_scale = qrcode_version == 1 ? 5 : 4;
    const uint8_t fragment_target_size = 105;
#endif

    // Make qr code icon as an overview image
    Icon qr_overview;
    qrcode_toIcon(&qrcode, &qr_overview, overview_scale);

    // Make a bag of icons for square fragments of the qr
    Icon* icons = NULL;
    size_t num_icons = 0;
    const bool show_grid = true;
    const uint8_t expected_grid_size = (qrcode_version == 1) ? 3 : 5;
    qrcode_toFragmentsIcons(&qrcode, fragment_target_size, show_grid, &icons, &num_icons);
    JADE_ASSERT(num_icons == expected_grid_size * expected_grid_size);

    // Show the overview and magnified fragments, and when the user
    // is done try to scan the qr code they have made and verify it
    // scans and the data imported matches the expected entropy.
    // NOTE: the gui activities are created and freed (by frequent calls to
    // gui_set_current_activity_ex()) inside the loop - this is less efficient
    // but keeps the maximum amout of free DRAM available at all times.
    // This is vital to prevent fragmentation occuring which then causes the large
    // allocations made by the qr-scanner to fail (even if there appears to be
    // sufficient DRAM available).
    bool retval = true;
    bool first_attempt = true;
    int32_t ev_id;
    while (true) {
        while (true) {
            // Show the overview QR
            uint8_t ipart = 0; // fragment to show
            gui_activity_t* const act_overview_qr = make_export_qr_overview_activity(&qr_overview, first_attempt);
            gui_set_current_activity_ex(act_overview_qr, true);
            if (gui_activity_wait_event(act_overview_qr, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                if (ev_id == BTN_QR_EXPORT_DONE) {
                    // We are done viewing/copying the qr
                    break;
                } else if (ev_id == BTN_QR_EXPORT_NEXT) {
                    // Move to fragments carousel, showing the first fragment
                    ipart = 0;
                } else if (ev_id == BTN_QR_EXPORT_PREV) {
                    if (first_attempt) {
                        // On the initial screen, 'back' takes us back out of these screens
                        // A false return implies a 'back' option was pressed.
                        retval = false;
                        goto cleanup;
                    } else {
                        // On subsequent loops through, the 'back' button goes back into
                        // the carousel of grid images, from the end (ie. backwards)
                        ipart = num_icons - 1;
                    }
                } else {
                    // Unexpected button event, continue waiting
                    continue;
                }
            } else {
                // Unexpected gui event, continue waiting
                continue;
            }
            first_attempt = false;

            // Make a screen to display qr-code fragment icons
            gui_view_node_t* icon_node = NULL;
            gui_view_node_t* text_node = NULL;
            gui_activity_t* const act_qr_part = make_export_qr_fragment_activity(&qr_overview, &icon_node, &text_node);
            JADE_ASSERT(icon_node);
            JADE_ASSERT(text_node);

            // Show QR parts, using the buttons to navigate to previous/next fragment
            while (true) {
                // Update display - ipart == num_icons implies going back to the 'overview' of the entire qr-code
                if (ipart < num_icons) {
                    char label[12];
                    const int ret = snprintf(label, sizeof(label), "Grid: %c%u", 'A' + (ipart / expected_grid_size),
                        1 + (ipart % expected_grid_size));
                    JADE_ASSERT(ret > 0 && ret < sizeof(label));
                    gui_update_icon(icon_node, icons[ipart], false);
                    gui_update_text(text_node, label);
                } else {
                    // Done showing fragments - back to qr overview screen
                    break;
                }

                gui_set_current_activity_ex(act_qr_part, true);
                if (gui_activity_wait_event(act_qr_part, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                    switch (ev_id) {
                    case BTN_QR_EXPORT_PREV:
                        ipart = (ipart + num_icons) % (num_icons + 1);
                        break;
                    case BTN_QR_EXPORT_NEXT:
                        ipart = (ipart + 1) % (num_icons + 1);
                        break;
                    default:
                        break;
                    }
                }
            }
        }

        // Verify QR by scanning it back
        qr_data_t qr_data = { .len = 0 };
        const qr_frame_guides_t qr_frame_guides = QR_GUIDES_SMALL;
        jade_camera_scan_qr(&qr_data, "Scan QR to verify", qr_frame_guides, "blkstrm.com/seedqr");
        if (qr_data.len == entropy_len && !memcmp(qr_data.data, entropy, entropy_len)) {
            // QR Code scanned, and it matched expected entropy
            const char* message[] = { "QR Code Verified" };
            await_message_activity(message, 1);
            *export_qr_verified = true;
            break; // done
        } else {
            const char* question[] = { qr_data.len ? "QR code does not match" : "No QR code captured", "Retry?" };
            if (await_skipyes_activity(NULL, question, 2, true, NULL)) {
                // User agreed to retry, so go back to displaying qr fragments
                continue;
            } else {
                // User decided to abandon, just break out of loop
                break;
            }
        }
    }

cleanup:
    // Free the icons
    for (int i = 0; i < num_icons; ++i) {
        free(icons[i].data);
    }
    free(icons);
    qrcode_freeIcon(&qr_overview);

    // Return 'true' if done, or 'false' if 'back' was pressed
    return retval;
}
#endif // CONFIG_HAS_CAMERA

// Function to change the mnemonic word separator and provide pointers to
// the start of the words.  Used when confirming one word at a time.
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

// Helper to display mnemonic words, and then have the user confirm some
// NOTE: this function replaces spaces with \0's in the passed mnemonic!
static bool display_confirm_mnemonic(const size_t nwords, char* mnemonic, const size_t mnemonic_len)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(mnemonic);

    // Show the warning banner screen, user to confirm
    const char* message[] = { "These words are your", "wallet. Keep them", "protected and offline." };
    if (!await_continueback_activity(NULL, message, 3, true, "blkstrm.com/phrase")) {
        // Abandon before we begin
        return false;
    }

    // Change the word separator to a null so we can treat each word as a terminated string.
    char* words[MNEMONIC_MAXWORDS]; // large enough for 12 and 24 word mnemonic
    change_mnemonic_word_separator(mnemonic, mnemonic_len, ' ', '\0', words, nwords);
    bool mnemonic_confirmed = false;

    // create the "show mnemonic" activities only once and then reuse them
    gui_activity_t* first_activity = NULL;
    gui_activity_t* last_activity = NULL;
    make_show_mnemonic_activities(&first_activity, &last_activity, words, nwords);
    JADE_ASSERT(first_activity);
    JADE_ASSERT(last_activity);

    while (!mnemonic_confirmed) {
        gui_set_current_activity(first_activity);
        int32_t ev_id;
        while (true) {
            ev_id = ESP_EVENT_ANY_ID;
            if (sync_await_single_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0) != ESP_OK) {
                continue;
            }
            if (ev_id == BTN_MNEMONIC_EXIT) {
                // User abandonded
                JADE_LOGD("user abandoned noting mnemonic");
                goto cleanup;
            }
            if (ev_id == BTN_MNEMONIC_VERIFY) {
                // User ready to verify mnemonic
                JADE_LOGD("moving on to confirm mnemonic");
                break;
            }
        }

        // Confirm the mnemonic - show groups of three consecutive words
        // and have user confirm one of them at random.
        // Ensures all words are at the very least displayed.
        mnemonic_confirmed = true; // will be set to false if wrong word selected
        const size_t num_words_options = nwords == MNEMONIC_MAXWORDS ? 8 : 6;
        for (size_t i = 0; i < nwords; i += 3) {
            const size_t offset_word_to_confirm = get_uniform_random_byte(3);
            const size_t selected = i + offset_word_to_confirm;
            gui_view_node_t* textbox = NULL;
            gui_activity_t* const confirm_act
                = make_confirm_mnemonic_word_activity(&textbox, i, offset_word_to_confirm, words, nwords);
            JADE_LOGD("selected = %u", selected);

            // Pick some other words from the mnemonic as options, but avoid
            // the words currently displayed on screen (neighbouring words).
            // Large enough for 12 and 24 word mnemonic
            bool already_picked[MNEMONIC_MAXWORDS] = { false };
            already_picked[i] = true;
            already_picked[i + 1] = true;
            already_picked[i + 2] = true;

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
                    index = (index + num_words_options - 1) % num_words_options;
                    gui_update_text(textbox, words[random_words[index]]);
                    break;

                case GUI_WHEEL_RIGHT_EVENT:
                    index = (index + 1) % num_words_options;
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
                const char* message[] = { "Incorrect. Check your", "recovery phrase and", "try again." };
                await_error_activity(message, 3);
                mnemonic_confirmed = false;
                break;
            }
        }
    }

    JADE_ASSERT(mnemonic_confirmed);
    JADE_LOGD("mnemonic confirmed");

cleanup:
    return mnemonic_confirmed;
}

#ifndef CONFIG_DEBUG_UNATTENDED_CI
// NOTE: only the English wordlist is supported.
static bool mnemonic_new(const size_t nwords, char* mnemonic, const size_t mnemonic_len)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(mnemonic);
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

    // Have user view and confirm mnemonic words
    const bool mnemonic_confirmed = display_confirm_mnemonic(nwords, new_mnemonic, new_mnemonic_len);

    SENSITIVE_POP(new_mnemonic);
    JADE_WALLY_VERIFY(wally_free_string(new_mnemonic));

    return mnemonic_confirmed;
}
#endif // CONFIG_DEBUG_UNATTENDED_CI

// NOTE: only the English wordlist is supported.
static void enable_relevant_chars(const bool is_mnemonic, const char* word, const size_t word_len,
    const size_t* filter_word_list, const size_t filter_word_list_size, gui_activity_t* act, gui_view_node_t* backspace,
    gui_view_node_t* enter, gui_view_node_t** btns, const size_t btns_len)
{
    JADE_ASSERT(word);
    // word_len may be zero if no word entered as yet
    // input_wordlist is optional
    JADE_ASSERT(filter_word_list || !filter_word_list_size);
    JADE_ASSERT(act);
    JADE_ASSERT(backspace);
    JADE_ASSERT(enter);
    JADE_ASSERT(btns);
    JADE_ASSERT(btns_len == 26); // ie A->Z

    JADE_ASSERT(backspace->activity == act);
    JADE_ASSERT(enter->activity == act);

    JADE_LOGD("word = %s, word_len = %u", word, word_len);

    // Enable enter if a) not entering a mnemonic, and b) not part-way through entering a word
    // Enable backspace in all cases.
    gui_set_active(enter, !is_mnemonic && !word_len);
    gui_set_active(backspace, true);

    // TODO: are there any invalid characters to start the word?

    // No characters currently selected (ie. no word stem)
    bool enabled[26] = { false };
    uint8_t num_enabled = 0;

    // If an 'filter_word_list' is passed, we iterate that and use the entries as a lookup
    // into the bip39 wordlist - if not passed we iterate the entire bip39 wordlist directly.
    const size_t limit = filter_word_list ? filter_word_list_size : BIP39_WORDLIST_LEN;
    for (size_t index = 0; index < limit; ++index) {
        const size_t wordlist_index = filter_word_list ? filter_word_list[index] : index;
        JADE_ASSERT(wordlist_index < BIP39_WORDLIST_LEN);

        // TODO: check strlen(wordlist_extracted)
        const char* wordlist_extracted = bip39_get_word_by_index(NULL, wordlist_index);
        JADE_ASSERT(wordlist_extracted);

        // If we have the first letter(s) typed, we can a) skip all preceding words
        // and also b) exit once we have passed beyond the relevant words.
        if (word_len > 0) {
            const int32_t res = strncmp(wordlist_extracted, word, word_len);
            if (res < 0) {
                // Not yet reached words with 'word' stem - loop to next word
                continue;
            } else if (res > 0) {
                // Gone past words with 'word' stem - may as well break
                break;
            }
        }

        // Wordlist word starts with given 'word' stem
        // See what the next letter is, and ensure that character is enabled
        // (Consider first letter of word if no given stem).
        const size_t char_index = wordlist_extracted[word_len] - 'a';
        if (!enabled[char_index]) {
            enabled[char_index] = true;
            ++num_enabled;
        }
    }
    JADE_ASSERT(num_enabled > 0);

    // Select a random active letter as the selected one
    uint8_t iselected = get_uniform_random_byte(num_enabled);
    gui_view_node_t* selected = NULL;
    for (size_t i = 0; i < btns_len; ++i) {
        JADE_ASSERT(btns[i]->activity == act);

        // Set item to select
        if (enabled[i] && !iselected--) {
            JADE_ASSERT(!selected);
            selected = btns[i];
        }
    }
    JADE_ASSERT(selected);

    // Update the ui
    gui_activity_set_active_selection(act, btns, btns_len, enabled, selected);
}

// NOTE: only the English wordlist is supported.
static size_t valid_words(const char* word, const size_t word_len, const size_t* filter_word_list,
    const size_t filter_word_list_size, size_t* output_word_list, const size_t output_word_list_len, bool* exact_match)
{
    JADE_ASSERT(word);
    // word_len may be zero if no word entered as yet
    // input_wordlist is optional
    JADE_ASSERT(filter_word_list || !filter_word_list_size);
    JADE_ASSERT(output_word_list);
    JADE_ASSERT(output_word_list_len);
    JADE_ASSERT(exact_match);

    *exact_match = false;
    size_t num_possible_words = 0;

    // If no word stem or filter_word_list is given we can trivially return 'the whole wordlist'
    if (!word_len && !filter_word_list) {
        for (size_t i = 0; i < output_word_list_len; ++i) {
            output_word_list[i] = i;
        }
        return BIP39_WORDLIST_LEN;
    }

    // Otherwise we need to check the word prefixes match
    // If an 'filter_word_list' is passed, we iterate that and use the entries as a lookup
    // into the bip39 wordlist - if not passed we iterate the entire bip39 wordlist directly.
    const size_t limit = filter_word_list ? filter_word_list_size : BIP39_WORDLIST_LEN;
    for (size_t index = 0; index < limit; ++index) {
        const size_t wordlist_index = filter_word_list ? filter_word_list[index] : index;
        JADE_ASSERT(wordlist_index < BIP39_WORDLIST_LEN);

        // TODO: check strlen(wordlist_extracted)
        const char* wordlist_extracted = bip39_get_word_by_index(NULL, wordlist_index);
        JADE_ASSERT(wordlist_extracted);

        // Test if passed 'word' is a valid prefix of the wordlist word
        const int32_t res = strncmp(wordlist_extracted, word, word_len);

        if (res < 0) {
            // No there yet, continue to next word
            continue;
        } else if (res > 0) {
            // Too late - gone past word - may as well abandon
            break;
        }

        // If prefix matches, see if it is an exact match for the entire word
        // (ie. word lengths are also same)
        if (wordlist_extracted[word_len] == '\0') {
            JADE_ASSERT(!num_possible_words); // should only happen on first match ...
            JADE_ASSERT(!*exact_match); // and so should only happen at most once!
            *exact_match = true;
        }

        // Return at most first output_word_list_len compatible words
        if (num_possible_words < output_word_list_len) {
            output_word_list[num_possible_words] = wordlist_index;
        }

        ++num_possible_words;
    }

    return num_possible_words;
}

// NOTE: only the English wordlist is supported.
static size_t valid_final_words(const char** mnemonic_words, const size_t num_mnemonic_words,
    size_t* possible_word_list, const size_t possible_word_list_len)
{
    JADE_ASSERT(mnemonic_words);
    JADE_ASSERT(num_mnemonic_words == 11 || num_mnemonic_words == 23);
    JADE_ASSERT(possible_word_list);
    JADE_ASSERT(possible_word_list_len);

    // Copy the mnemonic-thus-far into a work area
    char buf[MNEMONIC_BUFLEN];
    size_t offset = 0;
    for (size_t i = 0; i < num_mnemonic_words; ++i) {
        const size_t remaining = sizeof(buf) - offset;
        const int ret = snprintf(buf + offset, remaining, mnemonic_words[i]);
        JADE_ASSERT(ret > 0 && ret < remaining);
        offset += ret;
        buf[offset++] = ' ';
    }

    size_t num_possible_words = 0;
    for (size_t wordlist_index = 0; wordlist_index < BIP39_WORDLIST_LEN; ++wordlist_index) {
        const char* wordlist_extracted = bip39_get_word_by_index(NULL, wordlist_index);
        JADE_ASSERT(wordlist_extracted);
        const size_t remaining = sizeof(buf) - offset;
        const int ret = snprintf(buf + offset, remaining, wordlist_extracted);
        JADE_ASSERT(ret >= 3 && ret < remaining && buf[offset + ret] == '\0');

        if (bip39_mnemonic_validate(NULL, buf) == WALLY_OK) {
            // Return first possible_word_list_len valid words
            if (num_possible_words < possible_word_list_len) {
                possible_word_list[num_possible_words] = wordlist_index;
            }
            ++num_possible_words;
        }
    }

    return num_possible_words;
}

// NOTE: only the English wordlist is supported.
static size_t get_wordlist_words(
    const wordlist_purpose_t purpose, const size_t nwords, char* output, const size_t output_len)
{
    // 'title' is optional (and will default if not provided)
    JADE_ASSERT(nwords <= MNEMONIC_MAXWORDS);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= (8 + 1) * nwords); // words plus trailing space

    // Only 12 and 24 word mnemonics are supported
    const bool is_mnemonic = (purpose == MNEMONIC_SIMPLE) || (purpose == MNEMONIC_ADVANCED);
    JADE_ASSERT(nwords == 12 || nwords == 24 || !is_mnemonic);

    gui_view_node_t* btns[26] = {};
    const size_t btns_len = sizeof(btns) / sizeof(btns[0]);
    gui_view_node_t *titletext = NULL, *textbox = NULL, *backspace = NULL, *enter = NULL;
    const bool show_enter_btn = !is_mnemonic; // Don't show 'done' button when entering mnemonic words
    gui_activity_t* const enter_word_activity
        = make_enter_wordlist_word_activity(&titletext, show_enter_btn, &textbox, &backspace, &enter, btns, btns_len);
    JADE_ASSERT(enter);
    enter->is_active = show_enter_btn;

    JADE_ASSERT(titletext);
    if (purpose == WORDLIST_PASSPHRASE) {
        // Fixed title for all words
        gui_update_text(titletext, "Enter Passphrase");
    }

    gui_view_node_t* text_selection = NULL;
    gui_view_node_t* label = NULL;
    const char* select_word_title = ((purpose == WORDLIST_PASSPHRASE) ? "Enter Passphrase" : "Recover Wallet");
    gui_activity_t* const choose_word_activity = make_carousel_activity(select_word_title, &label, &text_selection);
    int32_t ev_id;

    // For each word
    const char* wordlist_words[MNEMONIC_MAXWORDS] = { 0 };
    size_t word_index = 0;
    bool done_entering_words = false;
    while (word_index < nwords && !done_entering_words) {
        JADE_ASSERT(!wordlist_words[word_index]);

        // When in 'Advanced' mode, if this is the final mnemonic word, have the option to additionally
        // filter to valid final words - ie. ones where the checksum is correct for the mnemonic as a whole.
        const size_t* p_filter_words = NULL;
        size_t num_filter_words = 0;
        size_t final_words[MAX_NUM_FINAL_WORDS];
        bool random_first_selection_word = false;
        if (purpose == MNEMONIC_ADVANCED && word_index == nwords - 1) {
            gui_activity_t* const final_word_activity = make_calculate_final_word_activity();
            while (true) {
                gui_set_current_activity(final_word_activity);

                if (gui_activity_wait_event(
                        final_word_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                    if (ev_id == BTN_MNEMONIC_FINAL_WORD_EXISTING) {
                        // Do nothing/skip, just let user enter final word as per other words
                        break;
                    } else if (ev_id == BTN_MNEMONIC_FINAL_WORD_CALCULATE) {
                        // Fetch valid final words to use as additional filter
                        display_processing_message_activity();
                        num_filter_words
                            = valid_final_words(wordlist_words, word_index, final_words, MAX_NUM_FINAL_WORDS);
                        p_filter_words = final_words;
                        JADE_ASSERT(num_filter_words == (nwords == 12 ? 128 : 8)); // expected due to checksum bits

                        // When we select from the valid words, randomise the initally selected word
                        random_first_selection_word = true;
                        break;
                    } else if (ev_id == BTN_MNEMONIC_FINAL_WORD_HELP) {
                        await_qr_help_activity("blkstrm.com/finalword");
                    }
                }
            }
        }

        // Reset default title for next word when entering mnemonic phrase
        if (is_mnemonic) {
            char enter_word_title[16];
            const int ret = snprintf(enter_word_title, sizeof(enter_word_title), "Insert word %u", word_index + 1);
            JADE_ASSERT(ret > 0 && ret < sizeof(enter_word_title));
            gui_update_text(titletext, enter_word_title);
        }

        char word[16] = { 0 };
        size_t char_index = 0;
        gui_update_text(textbox, word);

        const size_t current_word_index = word_index;
        while (word_index == current_word_index && !done_entering_words) {
            JADE_ASSERT(!wordlist_words[word_index]);
            JADE_ASSERT(char_index < 6); // must have found a word by then!

            size_t possible_word_list[NUM_WORDS_SELECT];
            bool exact_match = false; // not interested in any case
            const size_t possible_words = valid_words(
                word, char_index, p_filter_words, num_filter_words, possible_word_list, NUM_WORDS_SELECT, &exact_match);
            JADE_ASSERT(possible_words > 0);

            bool selected_backspace = false;
            if (possible_words && possible_words <= NUM_WORDS_SELECT) {
                // 'Small' number of words - allow user to select from these words
                char choose_word_title[16];
                const int ret
                    = snprintf(choose_word_title, sizeof(choose_word_title), "Select word %u", word_index + 1);
                JADE_ASSERT(ret > 0 && ret < sizeof(choose_word_title));
                gui_update_text(label, choose_word_title);

                bool stop = false;
                uint8_t selected = random_first_selection_word ? get_uniform_random_byte(possible_words) : 0;
                const char* wordlist_extracted = NULL;
                while (!stop) {
                    JADE_ASSERT(selected <= possible_words);
                    JADE_ASSERT(!wordlist_extracted);

                    // Update current selection
                    if (selected == possible_words) { // delete
                        gui_set_text_font(text_selection, DEJAVU24_FONT);
                        gui_update_text(text_selection, "|");
                    } else {
                        // word from wordlist
                        wordlist_extracted = bip39_get_word_by_index(NULL, possible_word_list[selected]);
                        JADE_ASSERT(wordlist_extracted);
                        gui_set_text_font(text_selection, GUI_DEFAULT_FONT);
                        gui_update_text(text_selection, wordlist_extracted);
                    }

                    // Ensure activity displayed
                    gui_set_current_activity(choose_word_activity);

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
                        stop = (ev_id == gui_get_click_event());
                    }

                    // If looping to new word, NULL the current word
                    if (!stop && wordlist_extracted) {
                        wordlist_extracted = NULL;
                    }
                } // while !stop

                // Word (or backspace) selected
                JADE_ASSERT(selected <= possible_words);
                selected_backspace = (selected == possible_words);

                if (selected_backspace) {
                    JADE_ASSERT(!wordlist_extracted);
                } else {
                    // Store the matched word in the selected words array
                    JADE_ASSERT(wordlist_extracted);
                    JADE_ASSERT(!wordlist_words[word_index]);
                    wordlist_words[word_index++] = wordlist_extracted;
                    wordlist_extracted = NULL; // relinquish
                }
            } else {
                // 'Large' number of words for any typed stem - use keyboard screen to further restrict words

                // Update the typed word and ensure activity set as current
                if (is_mnemonic) {
                    // For a mnemonic, show only the current word
                    gui_update_text(textbox, word);
                } else {
                    // Otherwise show last 3 words
                    char buf[32];
                    const char* shown[3] = { "", "", "" };
                    if (word_index == 0) {
                        shown[0] = word;
                    } else if (word_index == 1) {
                        shown[0] = wordlist_words[0];
                        shown[1] = word;
                    } else if (word_index == 2) {
                        shown[0] = wordlist_words[word_index - 2];
                        shown[1] = wordlist_words[word_index - 1];
                        shown[2] = word;
                    } else if (char_index == 0) {
                        shown[0] = wordlist_words[word_index - 3];
                        shown[1] = wordlist_words[word_index - 2];
                        shown[2] = wordlist_words[word_index - 1];
                    } else {
                        shown[0] = wordlist_words[word_index - 2];
                        shown[1] = wordlist_words[word_index - 1];
                        shown[2] = word;
                    }
                    const bool show_ellipsis = (word_index > 3) || (word_index == 3 && char_index > 0);
                    const char* prefix = show_ellipsis ? "... " : "";
                    const int ret = snprintf(buf, sizeof(buf), "%s%s %s %s", prefix, shown[0], shown[1], shown[2]);
                    JADE_ASSERT(ret >= 0 && ret < sizeof(buf));
                    gui_update_text(textbox, buf);
                }
                gui_set_current_activity(enter_word_activity);

                // Update which letters are active/available
                JADE_ASSERT(is_mnemonic || !p_filter_words);
                enable_relevant_chars(is_mnemonic, word, char_index, p_filter_words, num_filter_words,
                    enter_word_activity, backspace, enter, btns, btns_len);

                // Wait for kb button click
                gui_activity_wait_event(enter_word_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
                selected_backspace = (ev_id == BTN_KEYBOARD_BACKSPACE);
                done_entering_words = (ev_id == BTN_KEYBOARD_ENTER);
                if (!selected_backspace && !done_entering_words) {
                    // Character/letter was clicked
                    const char letter_selected = ev_id - BTN_KEYBOARD_ASCII_OFFSET;
                    if (letter_selected >= 'A' && letter_selected <= 'Z') {
                        word[char_index] = tolower(letter_selected);
                        word[++char_index] = '\0';
                    }
                }
            }

            // Handle any backspace/delete option
            if (selected_backspace) {
                JADE_ASSERT(!done_entering_words);

                if (char_index > 0) {
                    // Go back one character
                    word[--char_index] = '\0';
                } else if (word_index > 0) {
                    // Deleting when no characters entered for this word
                    // Go back to previous word - this breaks outof the  'per character'
                    // loop so we go back round the outer 'per word' loop.
                    JADE_ASSERT(!wordlist_words[word_index]);
                    --word_index;

                    // NULL the cached previous word, as we start that one from scratch
                    JADE_ASSERT(wordlist_words[word_index]);
                    wordlist_words[word_index] = NULL;
                } else {
                    // Backspace at start of first word -
                    // - if entering a mnemonic, abandon mnemonic entry back to previous screen
                    // - if not entering a mnemonic, ignore this button at this time - user can
                    //   use 'enter' button to select empty string / no words.
                    JADE_ASSERT(!wordlist_words[word_index]);
                    if (is_mnemonic) {
                        return 0; // no words entered
                    }
                }
            }
        } // cycle on characters
    } // cycle on words

    // If entering mnemonic should have 'nwords' word indices in 'wordlist_words'
    const size_t words_entered = word_index;
    JADE_ASSERT(words_entered == nwords || !is_mnemonic);

    // Convert array of wally wordlist strings to a single string
    size_t offset = 0;
    for (word_index = 0; word_index < words_entered; ++word_index) {
        if (offset > 0) {
            output[offset++] = ' ';
        }
        const int ret = snprintf(output + offset, output_len - offset, wordlist_words[word_index]);
        JADE_ASSERT(ret > 0 && ret < output_len - offset);
        offset += ret;
    }
    return words_entered;
}

#ifndef CONFIG_DEBUG_UNATTENDED_CI
// NOTE: only the English wordlist is supported.
static bool mnemonic_recover(const size_t nwords, const bool advanced_mode, char* mnemonic, const size_t mnemonic_len)
{
    // Support 12-word and 24-word mnemonics only
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(mnemonic_len == MNEMONIC_BUFLEN);

    const wordlist_purpose_t purpose = advanced_mode ? MNEMONIC_ADVANCED : MNEMONIC_SIMPLE;
    const size_t words_entered = get_wordlist_words(purpose, nwords, mnemonic, mnemonic_len);

    if (!words_entered) {
        // Mnemonic entry abandoned
        return false;
    }

    if (words_entered != nwords || bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
        // Invalid mnemonic entered
        JADE_LOGW("Invalid mnemonic entered");
        const char* message[] = { "Invalid recovery phrase" };
        await_error_activity(message, 1);
        return false;
    }

    return true;
}
#endif // CONFIG_DEBUG_UNATTENDED_CI

// Take a nul terminated string of space-separated mnemonic-word prefixes, and populate a string of
// space-separated full mnemonic words (also nul terminated).
// Returns true if it works!  Returns false if any of the prefixes are not a prefix for exactly one
// valid mnemonic word, or if the expanded string is too large for the provided buffer.
// NOTE: There are a load of three-letter words in the bip39 list that are a) valid words in their
// own right, and also b) prefixes to other words.
// eg: bar, barely, bargain, barrel; pen, penalty, pencil; ski, skill, skin, skirt
// In this case we allow/prefer an exact match even when the word is an prefix of other words.
// NOTE: only the English wordlist is supported.
static bool expand_words(const uint8_t* bytes, const size_t bytes_len, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(buf);
    JADE_ASSERT(buf_len);
    JADE_INIT_OUT_SIZE(written);

    JADE_ASSERT(bytes[bytes_len] == '\0');

    size_t write_pos = 0;
    const char* read_ptr = (const char*)bytes;
    const char* end_ptr = read_ptr;

    // Must be a string of printable characters
    if (!string_all((const char*)bytes, isprint)) {
        return false;
    }

    while (*end_ptr != '\0' && write_pos < buf_len) {
        // Find the end of this word/prefix
        end_ptr = strchr(read_ptr, ' ');
        if (!end_ptr) {
            // Not found, point to end of string
            end_ptr = (const char*)bytes + bytes_len;
            JADE_ASSERT(*end_ptr == '\0');
        }
        JADE_ASSERT(end_ptr <= (const char*)bytes + bytes_len);

        // Lookup prefix in the default (English) wordlist, ensuring exactly one match
        size_t possible_match = 0;
        bool exact_match = false;
        const size_t nmatches = valid_words(read_ptr, (end_ptr - read_ptr), NULL, 0, &possible_match, 1, &exact_match);
        if (nmatches != 1 && !exact_match) {
            JADE_LOGW("%d matches for prefix: %.*s", nmatches, (end_ptr - read_ptr), read_ptr);
            return false;
        }

        const char* wordlist_extracted = bip39_get_word_by_index(NULL, possible_match);
        JADE_ASSERT(wordlist_extracted);
        const size_t word_len = strlen(wordlist_extracted);
        if (write_pos + word_len >= buf_len) {
            JADE_LOGW("Expanded mnemonic too long");
            return false;
        }

        // Copy the expanded word into the output buffer
        memcpy(buf + write_pos, wordlist_extracted, word_len);
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

static bool import_bcur_bip39(
    const uint8_t* bytes, const size_t bytes_len, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(buf);
    JADE_ASSERT(buf_len);
    JADE_INIT_OUT_SIZE(written);

    JADE_ASSERT(bytes[bytes_len] == '\0');

    // Quick check to see if it looks like a bcur bip39 string
    const char bcqrtag[] = "UR:CRYPTO-BIP39";
    if (bytes_len <= sizeof(bcqrtag) || strncasecmp(bcqrtag, (const char*)bytes, sizeof(bcqrtag) - 1)) {
        return false;
    }

    // Decode bcur string
    return bcur_parse_bip39_wrapper((const char*)bytes, bytes_len, buf, buf_len, written);
}

// SeedSigner SeedQR support (ie string of 4-digit word indices).
// NOTE: only the English wordlist is supported.
static bool import_seedqr(
    const uint8_t* bytes, const size_t bytes_len, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(buf);
    JADE_ASSERT(buf_len);
    JADE_INIT_OUT_SIZE(written);

    JADE_ASSERT(bytes[bytes_len] == '\0');

    // Must be a string of appropriate length and all digits
    if ((bytes_len != 48 && bytes_len != 96) || !string_all((const char*)bytes, isdigit)) {
        return false;
    }

    // Read out 4-digit (ie. 0-padded) indices, and lookup word
    char index_code[5];
    SENSITIVE_PUSH(index_code, sizeof(index_code));
    index_code[4] = '\0';

    size_t write_pos = 0;
    const size_t num_words = bytes_len == 48 ? 12 : 24;
    for (size_t i = 0; i < num_words; ++i) {
        memcpy(index_code, bytes + (i * 4), 4);
        const size_t index = strtol(index_code, NULL, 10);
        if (index > 2047) {
            JADE_LOGE("Error, provided a bip39 word out of range");
            SENSITIVE_POP(index_code);
            return false;
        }

        const char* wordlist_extracted = bip39_get_word_by_index(NULL, index);
        JADE_ASSERT(wordlist_extracted);
        const size_t wordlen = strlen(wordlist_extracted);
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
        memcpy(buf + write_pos, wordlist_extracted, wordlen);
        write_pos += wordlen;
    }

    SENSITIVE_POP(index_code);
    buf[write_pos++] = '\0';
    *written = write_pos;
    return true;
}

// SeedSigner CompactSeedQR support (ie raw entropy).
// NOTE: only the English wordlist is supported.
static bool import_compactseedqr(
    const uint8_t* bytes, const size_t bytes_len, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(buf);
    JADE_ASSERT(buf_len);
    JADE_INIT_OUT_SIZE(written);

    // Any buffer of appropriate length will work as a compactseedqr as it's just raw entropy
    if ((bytes_len != BIP32_ENTROPY_LEN_128 && bytes_len != BIP32_ENTROPY_LEN_256)) {
        return false;
    }

    // Convert binary entropy to mnemonic string
    char* mnemonic = NULL;
    JADE_WALLY_VERIFY(bip39_mnemonic_from_bytes(NULL, bytes, bytes_len, &mnemonic));
    JADE_ASSERT(mnemonic);
    const size_t mnemonic_len = strnlen(mnemonic, buf_len);
    JADE_ASSERT(mnemonic_len < buf_len); // buffer should be large enough for any mnemonic

    // Copy into output buffer and zero and free wally string
    strcpy(buf, mnemonic);
    *written = mnemonic_len + 1; // Report actual number of bytes written including the nul-terminator

    JADE_WALLY_VERIFY(wally_bzero(mnemonic, mnemonic_len));
    JADE_WALLY_VERIFY(wally_free_string(mnemonic));
    return true;
}

// Attempt to import mnemonic from supported formats
bool import_mnemonic(const uint8_t* bytes, const size_t bytes_len, char* buf, const size_t buf_len, size_t* written)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(buf);
    JADE_INIT_OUT_SIZE(written);

    JADE_ASSERT(bytes[bytes_len] == '\0');

    // 1. Try seedsigner compact format (ie. raw 128bit or 256bit entropy)
    // 2. Try seedsigner standard format (string of 4-digit indicies, no spaces)
    // 3. Try bcur bip39 format (starts with a specific string prefix)
    // 4. Try to read word prefixes or whole words (space separated)
    return import_compactseedqr(bytes, bytes_len, buf, buf_len, written)
        || import_seedqr(bytes, bytes_len, buf, buf_len, written)
        || import_bcur_bip39(bytes, bytes_len, buf, buf_len, written)
        || expand_words(bytes, bytes_len, buf, buf_len, written);
}

// Function to validate qr scanned is (or expands to) a valid mnemonic
// (Passed to the qr-scanner so scanning only stops when this is satisfied)
// NOTE: not 'static' here as also called from debug/test code.
bool import_and_validate_mnemonic(qr_data_t* qr_data)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(qr_data->len < sizeof(qr_data->data));
    JADE_ASSERT(qr_data->data[qr_data->len] == '\0');

    char buf[sizeof(qr_data->data)];
    SENSITIVE_PUSH(buf, sizeof(buf));

    // Try to import mnemonic, validate, and if all good copy over into the qr_data
    size_t written = 0;
    if (import_mnemonic(qr_data->data, qr_data->len, buf, sizeof(buf), &written)
        && bip39_mnemonic_validate(NULL, buf) == WALLY_OK) {
        JADE_ASSERT(written);
        JADE_ASSERT(written <= sizeof(buf));
        JADE_ASSERT(buf[written - 1] == '\0');

        memcpy(qr_data->data, buf, written);
        qr_data->len = written - 1; // Do not include nul-terminator

        SENSITIVE_POP(buf);
        return true;
    }

    // Show the user that a valid qr was scanned, but the string data
    // did not constitute (or expand to) a valid bip39 mnemonic string.
    SENSITIVE_POP(buf);

    const char* message[] = { "Invalid recovery phrase" };
    await_error_activity(message, 1);
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

    // We return 'true' if we scanned any string data at all
    const qr_frame_guides_t qr_frame_guides = QR_GUIDES_SMALL;
    const bool qr_scanned
        = jade_camera_scan_qr(&qr_data, NULL, qr_frame_guides, "blkstrm.com/scanwallet") && qr_data.len > 0;
    if (!qr_scanned) {
        JADE_LOGW("No qr code scanned");
        goto cleanup;
    }

    if (qr_data.len >= mnemonic_len) {
        JADE_LOGW("String data from qr unexpectedly long - ignored: %u", qr_data.len);
        goto cleanup;
    }

    // Result looks good, copy into mnemonic buffer
    JADE_ASSERT(qr_data.data[qr_data.len] == '\0');
    strcpy(mnemonic, (const char*)qr_data.data);

cleanup:
    SENSITIVE_POP(&qr_data);
    return qr_scanned;
}

static void get_freetext_passphrase(char* passphrase, const size_t passphrase_len)
{
    JADE_ASSERT(passphrase);
    JADE_ASSERT(passphrase_len);
    passphrase[0] = '\0';

    // We will need this activity later when confirming
    gui_view_node_t* text_to_confirm = NULL;
    gui_activity_t* const confirm_passphrase_activity = make_confirm_passphrase_activity(passphrase, &text_to_confirm);
    int32_t ev_id;

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

        // Ask user to confirm passphrase
        gui_update_text(text_to_confirm, kb_entry.len > 0 ? kb_entry.strdata : "<no passphrase>");
        gui_set_current_activity(confirm_passphrase_activity);
        gui_activity_wait_event(confirm_passphrase_activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
        done = (ev_id == BTN_YES);
    }

    JADE_ASSERT(kb_entry.len < passphrase_len);
    strcpy(passphrase, kb_entry.strdata);
}

void get_passphrase(char* passphrase, const size_t passphrase_len)
{
    JADE_ASSERT(passphrase);
    JADE_ASSERT(passphrase_len);
    passphrase[0] = '\0';

    if (keychain_get_passphrase_freq() == PASSPHRASE_NEVER) {
        // Auto apply the empty passphrase - return empty immediately
        return;
    }

    // Ask user to enter passphrase
    if (keychain_get_passphrase_type() == PASSPHRASE_WORDLIST) {
        // Passphrase made up only of bip39 wordlist words
        const size_t nwords
            = get_wordlist_words(WORDLIST_PASSPHRASE, WORDLIST_PASSPHRASE_MAX_WORDS, passphrase, passphrase_len);
        JADE_LOGI("%u wordlist words used for passphrase", nwords);
    } else {
        // Free-text passphrase
        get_freetext_passphrase(passphrase, passphrase_len);
    }
}

bool derive_keychain(const bool temporary_restore, const char* mnemonic)
{
    JADE_ASSERT(mnemonic);
    // NOTE: mnemnonic should be valid at this point for best UX

    keychain_t keydata = { 0 };
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // Get any passphrase, if relevant
    char passphrase[PASSPHRASE_MAX_LEN + 1]; // max chars plus '\0'
    SENSITIVE_PUSH(passphrase, sizeof(passphrase));
    passphrase[0] = '\0';

    get_passphrase(passphrase, sizeof(passphrase));
    const size_t passphrase_len = strnlen(passphrase, sizeof(passphrase));
    JADE_ASSERT(passphrase_len < sizeof(passphrase));

    display_processing_message_activity();

    // If the mnemonic is valid derive temporary keychain from it.
    // Otherwise break/return here.
    const bool wallet_created = keychain_derive_from_mnemonic(mnemonic, passphrase, &keydata);
    SENSITIVE_POP(passphrase);

    if (!wallet_created) {
        SENSITIVE_POP(&keydata);
        JADE_LOGE("Failed to derive wallet");
        return false;
    }

    // All good - push temporary into main in-memory keychain
    // and remove the restriction on network-types.
    keychain_set(&keydata, SOURCE_NONE, temporary_restore);
    keychain_clear_network_type_restriction();

    SENSITIVE_POP(&keydata);
    return true;
}

void initialise_with_mnemonic(const bool temporary_restore, const bool force_qr_scan, bool* offer_qr_temporary)
{
    // At this point we should not have any keys in-memory
    JADE_ASSERT(!keychain_get());
    JADE_ASSERT(offer_qr_temporary);

    // Initially false, set after wallet creation depending on path/routes/options
    *offer_qr_temporary = false;

    // We only allow setting new keys when encrypted keys are persisted if
    // we are doing a temporary restore.
    JADE_ASSERT(temporary_restore || !keychain_has_pin());

    char mnemonic[MNEMONIC_BUFLEN]; // buffer should be large enough for any mnemonic
    SENSITIVE_PUSH(mnemonic, sizeof(mnemonic));

    // NOTE: temporary wallets default to 'advanced mode'
    bool advanced_mode = temporary_restore;
    bool qr_scanned = force_qr_scan;
    gui_activity_t* act = NULL;
    if (force_qr_scan) {
        // Jump directly to scan-qr
        if (!mnemonic_qr(mnemonic, sizeof(mnemonic))) {
            // User abandoned scanning
            goto cleanup;
        }
    } else {
        // Initial welcome screen, or straight to 'recovery' screen if doing temporary restore
        const char* message[] = { "For setup instructions", "visit blockstream.com/", "jade" };
        if (temporary_restore) {
            act = make_restore_mnemonic_activity(temporary_restore);
        } else if (await_continueback_activity(NULL, message, 3, true, "blkstrm.com/jade")) {
            act = make_mnemonic_setup_type_activity();
        } else {
            // User decided against it
            goto cleanup;
        }

        bool got_mnemonic = false;
        while (!got_mnemonic) {
            gui_set_current_activity_ex(act, true);

            // In a debug unattended ci build, use hardcoded mnemonic after a short delay
            int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
            const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
            JADE_ASSERT(ret);

            switch (ev_id) {
            case BTN_MNEMONIC_EXIT:
                // Abandon setting up mnemonic altogether
                goto cleanup;

            // Change screens and continue to await button events
            case BTN_MNEMONIC_TYPE:
                advanced_mode = false;
                act = make_mnemonic_setup_type_activity();
                continue;

            case BTN_MNEMONIC_ADVANCED:
                const char* message[] = { "Technical features", "will be presented.", "Proceed with caution." };
                advanced_mode = await_continueback_activity("Advanced Setup", message, 3, true, "blkstrm.com/advanced");
                if (advanced_mode) {
                    act = make_mnemonic_setup_method_activity(advanced_mode);
                } else {
                    act = make_mnemonic_setup_type_activity();
                }
                continue;

            case BTN_MNEMONIC_METHOD:
                act = make_mnemonic_setup_method_activity(advanced_mode);
                continue;

            case BTN_NEW_MNEMONIC:
                act = make_new_mnemonic_activity();
                continue;

            case BTN_RESTORE_MNEMONIC:
                act = make_restore_mnemonic_activity(temporary_restore);
                continue;

            // Await user mnemonic entry/confirmation
            case BTN_NEW_MNEMONIC_12:
                got_mnemonic = mnemonic_new(12, mnemonic, sizeof(mnemonic));
                break;

            case BTN_NEW_MNEMONIC_24:
                got_mnemonic = mnemonic_new(24, mnemonic, sizeof(mnemonic));
                break;

            case BTN_RESTORE_MNEMONIC_12:
                got_mnemonic = mnemonic_recover(12, advanced_mode, mnemonic, sizeof(mnemonic));
                break;

            case BTN_RESTORE_MNEMONIC_24:
                got_mnemonic = mnemonic_recover(24, advanced_mode, mnemonic, sizeof(mnemonic));
                break;

            case BTN_RESTORE_MNEMONIC_QR:
                got_mnemonic = mnemonic_qr(mnemonic, sizeof(mnemonic));
                qr_scanned = got_mnemonic;
                break;

            default:
                // Unknown event, ignore
                continue;
            }
#else
            gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
                CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
            strcpy(mnemonic,
                "fish inner face ginger orchard permit useful method fence kidney chuckle party favorite sunset draw "
                "limb "
                "science crane oval letter slot invite sadness banana");
            got_mnemonic = true;
#endif
        }
    }

    // Mnemonic should be populated and *valid* at this point
    // a. newly created mnemonics should always be valid
    // b. restore by kb-entry includes explicit validation
    // c. qr-scanner includes a validation check before returning the scanned mnemonic
    if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
        JADE_LOGE("Invalid mnemonic unexpected");
        const char* message[] = { "Invalid recovery phrase" };
        await_error_activity(message, 1);
        goto cleanup;
    }

#ifdef CONFIG_HAS_CAMERA
    // Offer export via qr for true Jade hw's (ie. with camera) and the flag is set
    // ie. a) if 'Advanced' setup was used, and b) we did not already scan a QR
    if (advanced_mode) {
        // If the user scanned a qr for a non-temporary login, we may double-check
        // they don't prefer the temporary qr-mode wallet, in case that's what they intended.
        *offer_qr_temporary = qr_scanned && !temporary_restore;

        // If the user did not scan a QR, offer the chance to export (ie. draw) one now
        if (!qr_scanned) {
            const char* question[] = { "Export recovery phrase", "as a CompactSeedQR?" };
            bool export_qr = await_yesno_activity(NULL, question, 2, true, "blkstrm.com/seedqr");

            bool export_qr_verified = false;
            while (export_qr) {
                // Call export function - it returns 'true' when the step is complete (or skipped)
                // (it returns 'false' if the user presses 'back' to restart the process)
                export_qr = !mnemonic_export_qr(mnemonic, &export_qr_verified);
            }

            // If the user successfully exported the qr for a non-temporary login, we may double-check
            // they don't prefer the temporary qr-mode wallet, in case that's what they intended.
            *offer_qr_temporary = export_qr_verified && !temporary_restore;
        }
    }
#else
    // Flag unused if no camera available - silence compiler warning
    (void)qr_scanned;
#endif // CONFIG_HAS_CAMERA

    // Set flag indicating whether we should ask the user before exporting the master blinding key
    // (In advanced mode we ask the user, in default/basic mode we always silently export the key.)
    keychain_set_confirm_export_blinding_key(advanced_mode);

    if (!derive_keychain(temporary_restore, mnemonic)) {
        // Error making wallet...
        JADE_LOGE("Failed to derive keychain from valid mnemonic");
        const char* message[] = { "Failed to create wallet" };
        await_error_activity(message, 1);
        goto cleanup;
    }

    if (!temporary_restore) {
        // We need to cache the root mnemonic entropy as it is this that we will persist
        // encrypted to local flash (requiring a passphrase to derive the wallet master key).
        keychain_cache_mnemonic_entropy(mnemonic);
    }

cleanup:
    SENSITIVE_POP(mnemonic);
}

// Function to calculate a bip85 bip39 mnemonic phrase
// Caller must free with 'wally_free_string()
// NOTE: only the English wordlist is supported.
void get_bip85_mnemonic(const uint32_t nwords, const uint32_t index, char** new_mnemonic)
{
    JADE_ASSERT(nwords == 12 || nwords == 24);
    JADE_ASSERT(index < BIP85_INDEX_MAX);
    JADE_INIT_OUT_PPTR(new_mnemonic);
    JADE_ASSERT(keychain_get());

    size_t entropy_len = 0;
    uint8_t entropy[HMAC_SHA512_LEN];
    SENSITIVE_PUSH(entropy, sizeof(entropy));
    wallet_get_bip85_bip39_entropy(nwords, index, entropy, sizeof(entropy), &entropy_len);
    JADE_ASSERT(entropy_len == (nwords == 12 ? BIP39_ENTROPY_LEN_128 : BIP39_ENTROPY_LEN_256));

    JADE_WALLY_VERIFY(bip39_mnemonic_from_bytes(NULL, entropy, entropy_len, new_mnemonic));
    JADE_ASSERT(new_mnemonic);
    SENSITIVE_POP(entropy);
}

// Offer the user the option to generate a bip39 recovery phrase using entropy
// calculated as per bip85.  User provides number of words and also path index.
// NOTE: only the English wordlist is supported.
void handle_bip85_mnemonic()
{
    JADE_ASSERT(keychain_get());

    const char* message[] = { "Create a new recovery", "phrase derived from", "wallet and index" };
    if (!await_continueback_activity("BIP85", message, 3, true, "blkstrm.com/bip85")) {
        // User declined
        return;
    }

    gui_activity_t* act = make_bip85_mnemonic_words_activity();
    uint8_t nwords = 0;
    int32_t ev_id;

    while (true) {
        gui_set_current_activity(act);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_BIP85_12_WORDS;
#endif

        if (ret) {
            if (ev_id == BTN_BIP85_12_WORDS) {
                nwords = 12;
                break;
            } else if (ev_id == BTN_BIP85_24_WORDS) {
                nwords = 24;
                break;
            } else if (ev_id == BTN_BIP85_EXIT) {
                // User declined
                return;
            }
        }
    }
    JADE_ASSERT(nwords == 12 || nwords == 24);

    // Fetch index (uses pin-entry screen)
    pin_insert_t pin_insert = { .initial_state = ZERO, .pin_digits_shown = true };
    make_pin_insert_activity(&pin_insert, "BIP85", "Index #:");
    JADE_ASSERT(pin_insert.activity);

    size_t index = 0;
    while (true) {
        reset_pin(&pin_insert, "BIP85");
        gui_set_current_activity(pin_insert.activity);
        if (!run_pin_entry_loop(&pin_insert)) {
            // User abandoned index entry
            JADE_LOGI("User abandoned selecting index");
            return;
        }

        // Get entered digits as single numeric value
        index = get_pin_as_number(&pin_insert);
        JADE_ASSERT(index < BIP85_INDEX_MAX);

        // User to confirm
        char buf[8];
        const int ret = snprintf(buf, sizeof(buf), "%u", index);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
        const char* message[] = { "BIP85 index selected:", buf };
        if (await_continueback_activity("BIP85", message, 2, true, "blkstrm.com/bip85")) {
            JADE_LOGI("BIP85 index number selected: %u", index);
            break;
        }
    }
    JADE_ASSERT(index < BIP85_INDEX_MAX);

    // Generate bip39 mnemonic phrase from bip85 entropy
    char* new_mnemonic = NULL;
    get_bip85_mnemonic(nwords, index, &new_mnemonic);
    JADE_ASSERT(new_mnemonic);
    const size_t mnemonic_len = strnlen(new_mnemonic, MNEMONIC_BUFLEN);
    JADE_ASSERT(mnemonic_len < MNEMONIC_BUFLEN);
    SENSITIVE_PUSH(new_mnemonic, mnemonic_len);

    // Display and confirm mnemonic phrase
    if (display_confirm_mnemonic(nwords, new_mnemonic, mnemonic_len)) {
        const char* message[] = { "Recovery Phrase", "Confirmed" };
        await_message_activity(message, 2);
    }

    // Cleanup
    SENSITIVE_POP(new_mnemonic);
    JADE_WALLY_VERIFY(wally_free_string(new_mnemonic));
}
