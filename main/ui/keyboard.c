#include <string.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

#define NUM_KEYBOARD_ROWS 3

#define KB_ENTRY_STRING_MAX_DISPLAY_LEN 16

static void make_keyboard_screen(link_activity_t* kb_screen_activity, const char* title, const keyboard_type_t kb_type,
    const bool has_shift_btn, gui_view_node_t** textbox)
{
    JADE_ASSERT(kb_screen_activity);
    // title is optional
    JADE_INIT_OUT_PPTR(textbox);

    gui_activity_t* act = NULL;
    gui_make_activity(&act, true, title);
    act->selectables_wrap = true; // allow the button cursor to wrap

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 25, 25);
    gui_set_parent(vsplit, act->root_node);

    // first row, message
    gui_view_node_t* text_bg;
    gui_make_fill(&text_bg, TFT_BLACK);
    gui_set_parent(text_bg, vsplit);

    gui_view_node_t* entered_phrase;
    gui_make_text_font(&entered_phrase, "", TFT_WHITE, UBUNTU16_FONT);
    gui_set_text_noise(entered_phrase, TFT_BLACK);
    gui_set_parent(entered_phrase, text_bg);
    gui_set_padding(entered_phrase, GUI_MARGIN_TWO_VALUES, 1, 4);
    gui_set_align(entered_phrase, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    *textbox = entered_phrase;

    // second row, keyboard
    const char* lines[NUM_KEYBOARD_ROWS];
    // NOTE: final three characters ('|', '>', 'S') are rendered in different symbols fonts
    // and are buttons for 'backspace', 'shift/next kb', and 'enter/done'  (see below)
    if (kb_type == KB_LOWER_CASE_CHARS) {
        lines[0] = "abcdefghij";
        lines[1] = "klmnopqrs";
        lines[2] = "tuvwxyz|>S";
        // 'sizes' ok
    } else if (kb_type == KB_UPPER_CASE_CHARS) {
        lines[0] = "ABCDEFGHIJ";
        lines[1] = "KLMNOPQRS";
        lines[2] = "TUVWXYZ|>S";
        // 'sizes' ok
    } else if (kb_type == KB_NUMBERS_SYMBOLS) {
        lines[0] = "1234567890";
        lines[1] = "!\"#$%&'()";
        lines[2] = "*+,-./|>S";
    } else if (kb_type == KB_REMAINING_SYMBOLS) {
        lines[0] = ":;<=>?@";
        lines[1] = "[\\]^_`~";
        lines[2] = "{|} |>S";
    } else {
        JADE_ASSERT_MSG(false, "Unhandled keyboard type: %d", kb_type);
    }

    gui_view_node_t* btnShift = NULL;
    for (size_t l = 0; l < NUM_KEYBOARD_ROWS; ++l) {
        const char* line = lines[l];
        const size_t linelen = strlen(line);

        gui_view_node_t* hsplit;
        gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 10, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24);
        gui_set_margins(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0,
            ((10 - linelen) * 10)); // offset each row depending on row length
        gui_set_parent(hsplit, vsplit);

        // Create 'keys'
        for (size_t c = 0; c < linelen; ++c) {
            // By default the 'event' is based on the ascii character displayed
            size_t btn_ev_id = BTN_KEYBOARD_ASCII_OFFSET + line[c];
            size_t font = UBUNTU16_FONT;

            // The last three buttons on the last row are exceptions
            // These are buttons for 'backspace', 'shift/next kb', and 'enter/done'
            // They are rendered in different fonts to display bespoke symbols,
            // and raise events specific to these actions.
            if (l == NUM_KEYBOARD_ROWS - 1 && c >= linelen - 3) {
                if (c == linelen - 3) {
                    btn_ev_id = BTN_KEYBOARD_BACKSPACE;
                    font = DEFAULT_FONT; // '|' becomes <backspace>
                } else if (c == linelen - 2) {
                    btn_ev_id = BTN_KEYBOARD_SHIFT;
                    font = JADE_SYMBOLS_16x16_FONT; // '>' becomes <right arrow>
                } else if (c == linelen - 1) {
                    btn_ev_id = BTN_KEYBOARD_ENTER;
                    font = VARIOUS_SYMBOLS_FONT; // 'S' becomes <tick>
                }
            }

            if (!has_shift_btn && btn_ev_id == BTN_KEYBOARD_SHIFT) {
                // No shift/next-kb button - just use blank/filler
                gui_view_node_t* filler;
                gui_make_fill(&filler, TFT_BLACK);
                gui_set_parent(filler, hsplit);
            } else {
                // Keyboard button as normal
                gui_view_node_t* btn;
                gui_make_button(&btn, TFT_BLACK, TFT_BLOCKSTREAM_DARKGREEN, btn_ev_id, NULL);
                gui_set_margins(btn, GUI_MARGIN_ALL_EQUAL, 2);
                gui_set_borders(btn, TFT_BLUE, 2, GUI_BORDER_ALL);
                gui_set_borders_selected_color(btn, TFT_BLOCKSTREAM_GREEN);
                gui_set_borders_inactive_color(btn, TFT_BLACK);
                gui_set_parent(btn, hsplit);

                gui_view_node_t* label;
                const char str[2] = { line[c], 0 };
                gui_make_text_font(&label, str, TFT_WHITE, font);
                gui_set_parent(label, btn);
                gui_set_align(label, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

                // 'Shift' button to move to next kb screen
                if (btn_ev_id == BTN_KEYBOARD_SHIFT) {
                    btnShift = btn;
                }
            }
        }
    }

    // Push details into the output structure
    kb_screen_activity->activity = act;
    kb_screen_activity->prev_button = NULL; // Add one ?
    kb_screen_activity->next_button = btnShift; // If we have one
}

// NOTE: the kbs and textboxes arrays must be the same length, as given by arrays_len
void make_keyboard_entry_activity(keyboard_entry_t* kb_entry, const char* title)
{
    JADE_ASSERT(kb_entry);
    JADE_ASSERT(kb_entry->num_kbs);
    // title is optional

    if (kb_entry->num_kbs == 1) {
        // Single kb screen, no need for kb screen 'linking'
        link_activity_t kb_screen_act = {};
        const bool has_next_kb_btn = false;
        make_keyboard_screen(
            &kb_screen_act, title, kb_entry->keyboards[0], has_next_kb_btn, &kb_entry->textbox_nodes[0]);
        kb_entry->activity = kb_screen_act.activity;
    } else {
        // Chain the loop of kb screen activities
        link_activity_t kb_screen_act = {};
        linked_activities_info_t act_info = {};

        const bool has_next_kb_btn = true;
        for (size_t i = 0; i < kb_entry->num_kbs; ++i) {
            make_keyboard_screen(
                &kb_screen_act, title, kb_entry->keyboards[i], has_next_kb_btn, &kb_entry->textbox_nodes[i]);
            gui_chain_activities(&kb_screen_act, &act_info);
        }

        // Link the activities in a loop so last->next == first
        kb_screen_act.activity = act_info.first_activity;
        gui_chain_activities(&kb_screen_act, &act_info);

        kb_entry->activity = act_info.first_activity;
    }

    kb_entry->current_kb = 0;
    kb_entry->strdata[0] = '\0';
    kb_entry->len = 0;
}

static inline bool ascii_sane(const int32_t c) { return c >= 32 && c < 128; }

// Show the last n characters of the text (ie. only display last n chars of a long string)
#define GUI_UPDATE_TEXTBOX()                                                                                           \
    do {                                                                                                               \
        const char* str_tail = kb_entry->len < KB_ENTRY_STRING_MAX_DISPLAY_LEN                                         \
            ? kb_entry->strdata                                                                                        \
            : kb_entry->strdata + kb_entry->len - KB_ENTRY_STRING_MAX_DISPLAY_LEN;                                     \
        gui_update_text(kb_entry->textbox_nodes[kb_entry->current_kb], str_tail);                                      \
    } while (false)

void run_keyboard_entry_loop(keyboard_entry_t* kb_entry)
{
    JADE_ASSERT(kb_entry);
    JADE_ASSERT(kb_entry->activity);
    JADE_ASSERT(kb_entry->num_kbs);
    JADE_ASSERT(kb_entry->max_allowed_len);
    JADE_ASSERT(kb_entry->max_allowed_len < sizeof(kb_entry->strdata));

    esp_event_handler_instance_t ctx;
    wait_event_data_t* wait_data = make_wait_event_data();
    esp_event_handler_instance_register(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, wait_data, &ctx);

    int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    // Place initial activity - ensure 'current-kb' counter is reset
    kb_entry->current_kb = 0;
    GUI_UPDATE_TEXTBOX();
    gui_set_current_activity(kb_entry->activity);

    while (true) {
        ev_id = ESP_EVENT_ANY_ID;
        if (sync_wait_event(wait_data, NULL, &ev_id, NULL, 0) != ESP_OK) {
            continue;
        }

        if (ev_id > BTN_KEYBOARD_ASCII_OFFSET) {
            const size_t chr = ev_id - BTN_KEYBOARD_ASCII_OFFSET;
            if (kb_entry->len < kb_entry->max_allowed_len && ascii_sane(chr)) {
                kb_entry->strdata[kb_entry->len] = (char)chr;
                kb_entry->strdata[++kb_entry->len] = '\0';
                GUI_UPDATE_TEXTBOX();
            }

        } else if (ev_id == BTN_KEYBOARD_BACKSPACE) {
            if (kb_entry->len > 0) {
                kb_entry->strdata[--kb_entry->len] = '\0';
                GUI_UPDATE_TEXTBOX();
            }

        } else if (ev_id == BTN_KEYBOARD_SHIFT) {
            // Switch to new keyboard page - ensure new screen textbox up to date
            kb_entry->current_kb = (kb_entry->current_kb + 1) % kb_entry->num_kbs;
            GUI_UPDATE_TEXTBOX();

        } else if (ev_id == BTN_KEYBOARD_ENTER) {
            // Done, break out of entry loop
            break;
        }
    }
#else
    sync_wait_event(wait_data, NULL, &ev_id, NULL, CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    strcpy(kb_entry->strdata, "abcdef");
    kb_entry->len = strlen(kb_entry->strdata);
#endif

    // Done
    esp_event_handler_instance_unregister(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, ctx);
    free_wait_event_data(wait_data);

    JADE_ASSERT(kb_entry->len <= kb_entry->max_allowed_len);
    JADE_ASSERT(kb_entry->strdata[kb_entry->len] == '\0' && strlen(kb_entry->strdata) == kb_entry->len);
}
