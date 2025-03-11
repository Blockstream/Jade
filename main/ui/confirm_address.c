#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

// Should the address be displayed a formatted grid, or as a single long string (traditional)
#define ADDRESS_STRING_GRID (CONFIG_DISPLAY_WIDTH >= 320)

// Max amount of address we can show on a single screen
#define MAX_DISPLAY_ADDRESS_LEN (ADDRESS_STRING_GRID ? 100 : 96)
#define MAX_ADDRESS_SCREENS 2

#if ADDRESS_STRING_GRID

#define ADDR_GRID_FONT GUI_DEFAULT_FONT
#define ADDR_GRID_TOPPAD 12
#define ADDR_GRID_X 5
#define ADDR_GRID_Y 5
#define ADDR_GRID_SIZE (ADDR_GRID_X * ADDR_GRID_Y)
#define ADDR_TEXTSPLITLEN (MAX_DISPLAY_ADDRESS_LEN / ADDR_GRID_SIZE)

// The length of the required buffer to hold 'len' characters
// with a nul-terminator injected every 'wordlen' characters, and
// at the very end.  eg. for "abcdefhij\0" -> "abc\0def\0ghi\0j\0"
#define SPLIT_TEXT_LEN(len, wordlen) (len + (len / wordlen) + 1)

// Helper to copy text from one buffer to another, where the destination has terminators every
// 'wordlen' chars, eg: "abcdefghi\0" -> "abc\0def\0ghi\0j\0"
// output 'num_words' is number of 'words' written - eg. 4
// output 'written' is number iof bytes written, including all '\0's - eg. 14
static void split_text(const char* src, const size_t len, const size_t wordlen, char* output, const size_t output_len,
    size_t* num_words, size_t* written)
{
    JADE_ASSERT(src);
    JADE_ASSERT(wordlen);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= SPLIT_TEXT_LEN(len, wordlen));
    JADE_INIT_OUT_SIZE(num_words);
    JADE_INIT_OUT_SIZE(written);

    size_t read = 0;
    size_t write = 0;
    while (read < len) {
        const size_t remaining = len - read;
        const size_t nchars = remaining > wordlen ? wordlen : remaining;

        JADE_ASSERT(write + nchars + 1 <= output_len);
        strncpy(output + write, src + read, nchars);
        read += nchars;
        write += nchars;

        output[write++] = '\0';
        ++*num_words;
    }
    JADE_ASSERT(write <= output_len);
    *written = write;
}
#endif // ADDRESS_STRING_GRID

// also used in sign_tx
gui_activity_t* make_display_address_activities(const char* title, const bool show_one_screen_tick, const char* address,
    const bool default_selection, gui_activity_t** actaddr2)
{
    JADE_ASSERT(address);
    JADE_INIT_OUT_PPTR(actaddr2);

    gui_activity_t* act;

    const size_t addrlen = strlen(address);
    JADE_ASSERT(addrlen <= MAX_ADDRESS_SCREENS * MAX_DISPLAY_ADDRESS_LEN);

#if ADDRESS_STRING_GRID
    size_t num_words = 0; // Number of 'words' string is split into
    size_t words_len = 0; // NOTE: words_len will include all included (incl.trailing) '\0'
    char address_words[SPLIT_TEXT_LEN(MAX_ADDRESS_SCREENS * MAX_DISPLAY_ADDRESS_LEN, ADDR_TEXTSPLITLEN)];
    split_text(address, addrlen, ADDR_TEXTSPLITLEN, address_words, sizeof(address_words), &num_words, &words_len);
    JADE_ASSERT(num_words <= MAX_ADDRESS_SCREENS * ADDR_GRID_SIZE);
    JADE_ASSERT(words_len <= sizeof(address_words));
#else
    char buf[1 + MAX_DISPLAY_ADDRESS_LEN + 1];
    const char* message[] = { buf };
#endif // ADDRESS_STRING_GRID

    if (addrlen <= MAX_DISPLAY_ADDRESS_LEN) {
        // Just one screen to show address
        btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_ADDRESS_REJECT },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ADDRESS_ACCEPT } };

        if (!show_one_screen_tick) {
            hdrbtns[1].txt = NULL;
            hdrbtns[1].ev_id = GUI_BUTTON_EVENT_NONE;
        }

#if ADDRESS_STRING_GRID
        JADE_ASSERT(num_words <= ADDR_GRID_SIZE);
        const char* remaining_words = NULL;
        act = make_text_grid_activity(title, hdrbtns, 2, ADDR_GRID_TOPPAD, ADDR_GRID_X, ADDR_GRID_Y, address_words,
            num_words, ADDR_GRID_FONT, &remaining_words);
        JADE_ASSERT(remaining_words == address_words + words_len); // all words consumed (displayed)
#else
        const int ret = snprintf(buf, sizeof(buf), "\n%s", address);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        act = make_show_message_activity(message, 1, title, hdrbtns, 2, NULL, 0);
#endif // ADDRESS_STRING_GRID

        gui_set_activity_initial_selection(show_one_screen_tick && default_selection ? hdrbtns[1].btn : hdrbtns[0].btn);
    } else {
        // Need two (MAX_ADDRESS_SCREENS) screens to show address
        // First screen 'confirm' button becomes 'next'
        btn_data_t hdrbtns1[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_ADDRESS_REJECT },
            { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_ADDRESS_NEXT } };

        char titlebuf[32];
        int ret = snprintf(titlebuf, sizeof(titlebuf), "%s (1/2)", title);
        JADE_ASSERT(ret > 0 && ret < sizeof(titlebuf));

#if ADDRESS_STRING_GRID
        JADE_ASSERT(num_words > ADDR_GRID_SIZE);
        const char* remaining_words = NULL;
        act = make_text_grid_activity(titlebuf, hdrbtns1, 2, ADDR_GRID_TOPPAD, ADDR_GRID_X, ADDR_GRID_Y, address_words,
            ADDR_GRID_SIZE, ADDR_GRID_FONT, &remaining_words);
        JADE_ASSERT(remaining_words > address_words);
        JADE_ASSERT(remaining_words < address_words + words_len); // Some words remaining
#else
        ret = snprintf(buf, sizeof(buf), "\n%.*s", MAX_DISPLAY_ADDRESS_LEN, address);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        act = make_show_message_activity(message, 1, titlebuf, hdrbtns1, 2, NULL, 0);
#endif // ADDRESS_STRING_GRID

        gui_set_activity_initial_selection(hdrbtns1[1].btn);

        // Second screen 'reject' button becomes 'back'
        btn_data_t hdrbtns2[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_BACK },
            { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_ADDRESS_ACCEPT } };

        ret = snprintf(titlebuf, sizeof(titlebuf), "%s (2/2)", title);
        JADE_ASSERT(ret > 0 && ret < sizeof(titlebuf));

#if ADDRESS_STRING_GRID
        const size_t num_p2words = num_words - ADDR_GRID_SIZE;
        *actaddr2 = make_text_grid_activity(titlebuf, hdrbtns2, 2, ADDR_GRID_TOPPAD, ADDR_GRID_X, ADDR_GRID_Y,
            remaining_words, num_p2words, ADDR_GRID_FONT, &remaining_words);
        JADE_ASSERT(remaining_words == address_words + words_len); // all words consumed (displayed)
#else
        ret = snprintf(buf, sizeof(buf), "\n%s", address + MAX_DISPLAY_ADDRESS_LEN);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));

        *actaddr2 = make_show_message_activity(message, 1, titlebuf, hdrbtns2, 2, NULL, 0);
#endif // ADDRESS_STRING_GRID

        gui_set_activity_initial_selection(default_selection ? hdrbtns2[1].btn : hdrbtns2[0].btn);
    }

    return act;
}

bool show_confirm_address_activity(const char* address, const bool default_selection)
{
    JADE_ASSERT(address);
    // warning_msg is optional

    const bool show_tick = true;
    gui_activity_t* act_addr2 = NULL;
    gui_activity_t* const act_addr1
        = make_display_address_activities("Verify Address", show_tick, address, default_selection, &act_addr2);

    gui_activity_t* act = act_addr1;
    int32_t ev_id;

    while (true) {
        gui_set_current_activity(act);

        // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_ADDRESS_ACCEPT;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_addr1;
                break;

            case BTN_ADDRESS_NEXT:
                act = act_addr2;
                break;

            case BTN_ADDRESS_REJECT:
                return false;

            case BTN_ADDRESS_ACCEPT:
                return true;
            }
        }
    }
}
