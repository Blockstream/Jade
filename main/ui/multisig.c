#include <inttypes.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"

#include <sodium/utils.h>

bool bip32_path_as_str(const uint32_t parts[], size_t num_parts, char* output, const size_t output_len);

// Translate a GUI button (ok/cancel) into a multisig_ JADE_EVENT (so the caller
// can await without worrying about which screen/activity it came from).
static void translate_event(void* handler_arg, esp_event_base_t base, int32_t id, void* unused)
{
    JADE_ASSERT(id == BTN_MULTISIG_EXIT || id == BTN_MULTISIG_CONFIRM);
    esp_event_post(
        JADE_EVENT, id == BTN_MULTISIG_CONFIRM ? MULTISIG_ACCEPT : MULTISIG_DECLINE, NULL, 0, 100 / portTICK_PERIOD_MS);
}

static void make_initial_confirm_screen(link_activity_t* link_activity, const char* multisig_name, const bool sorted,
    const size_t threshold, const size_t num_signers, const uint8_t* wallet_fingerprint,
    const size_t wallet_fingerprint_len)
{
    JADE_ASSERT(link_activity);
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(wallet_fingerprint);
    JADE_ASSERT(wallet_fingerprint_len == BIP32_KEY_FINGERPRINT_LEN);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Confirm Multisig");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* hsplit_text1;
    gui_make_hsplit(&hsplit_text1, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text1, vsplit);

    gui_view_node_t* text1a;
    gui_make_text(&text1a, "Name", TFT_WHITE);
    gui_set_parent(text1a, hsplit_text1);
    gui_set_align(text1a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* text1b;
    gui_make_text(&text1b, multisig_name, TFT_WHITE);
    gui_set_parent(text1b, hsplit_text1);
    gui_set_align(text1b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2a;
    gui_make_text(&text2a, "Type", TFT_WHITE);
    gui_set_parent(text2a, hsplit_text2);
    gui_set_align(text2a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    char type[16];
    int ret = snprintf(type, sizeof(type), "%uof%u", threshold, num_signers);
    JADE_ASSERT(ret > 0 && ret < sizeof(type));

    gui_view_node_t* text2b;
    gui_make_text(&text2b, type, TFT_WHITE);
    gui_set_parent(text2b, hsplit_text2);
    gui_set_align(text2b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* hsplit_text3;
    gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 35, 65);
    gui_set_parent(hsplit_text3, vsplit);

    gui_view_node_t* text3a;
    gui_make_text(&text3a, "Sorted", TFT_WHITE);
    gui_set_parent(text3a, hsplit_text3);
    gui_set_align(text3a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* text3b;
    gui_make_text(&text3b, sorted ? "Y" : "N", TFT_WHITE);
    gui_set_parent(text3b, hsplit_text3);
    gui_set_align(text3b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* hsplit_text4;
    gui_make_hsplit(&hsplit_text4, GUI_SPLIT_RELATIVE, 2, 35, 65);
    gui_set_parent(hsplit_text4, vsplit);

    gui_view_node_t* text4a;
    gui_make_text(&text4a, "Wallet", TFT_WHITE);
    gui_set_parent(text4a, hsplit_text4);
    gui_set_align(text4a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    char* fingerprint_hex;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(wallet_fingerprint, wallet_fingerprint_len, &fingerprint_hex));
    gui_view_node_t* text4b;
    gui_make_text(&text4b, fingerprint_hex, TFT_WHITE);
    gui_set_parent(text4b, hsplit_text4);
    gui_set_align(text4b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    JADE_WALLY_VERIFY(wally_free_string(fingerprint_hex));

    // Buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_MULTISIG_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, hsplit_btn);

    gui_view_node_t* textbtn2;
    gui_make_text(&textbtn2, "X", TFT_WHITE);
    gui_set_parent(textbtn2, btn2);
    gui_set_align(textbtn2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_MULTISIG_NEXT, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text(&textbtn3, ">", TFT_WHITE);
    gui_set_text_font(textbtn3, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Connect every screen's 'exit' button to the 'translate' handler above
    gui_activity_register_event(act, GUI_BUTTON_EVENT, BTN_MULTISIG_EXIT, translate_event, NULL);

    // Set the intially selected item to the 'Next' button (ie. btn3)
    gui_set_activity_initial_selection(act, btn3);

    // Push details into the output structure
    link_activity->activity = act;
    link_activity->prev_button = NULL;
    link_activity->next_button = btn3;
}

static void make_signer_activity(link_activity_t* link_activity, const size_t num_signers, const size_t index,
    const bool is_this_wallet, const signer_t* signer)
{
    JADE_ASSERT(link_activity);
    JADE_ASSERT(index <= num_signers);
    JADE_ASSERT(signer);

    gui_activity_t* act;
    char header[24];
    const int ret = snprintf(header, sizeof(header), "Signer %d/%d%s", index, num_signers, is_this_wallet ? " *" : "");
    JADE_ASSERT(ret > 0 && ret < sizeof(header));
    gui_make_activity(&act, true, header);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* hsplit_text1;
    gui_make_hsplit(&hsplit_text1, GUI_SPLIT_RELATIVE, 2, 35, 65);
    gui_set_parent(hsplit_text1, vsplit);

    gui_view_node_t* text1a;
    gui_make_text(&text1a, "Fingerprint", TFT_WHITE);
    gui_set_parent(text1a, hsplit_text1);
    gui_set_align(text1a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    char* fingerprint_hex;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(signer->fingerprint, sizeof(signer->fingerprint), &fingerprint_hex));
    gui_view_node_t* text1b;
    gui_make_text(&text1b, fingerprint_hex, TFT_WHITE);
    gui_set_parent(text1b, hsplit_text1);
    gui_set_align(text1b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    JADE_WALLY_VERIFY(wally_free_string(fingerprint_hex));

    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 35, 65);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2a;
    gui_make_text(&text2a, "Derivation", TFT_WHITE);
    gui_set_parent(text2a, hsplit_text2);
    gui_set_align(text2a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    char derivation[128];
    if (signer->derivation_len == 0) {
        strcpy(derivation, "[none provided]");
    } else if (!bip32_path_as_str(signer->derivation, signer->derivation_len, derivation, sizeof(derivation))) {
        strcpy(derivation, "[too long]");
    }

    gui_view_node_t* text2b;
    gui_make_text(&text2b, derivation, TFT_WHITE);
    gui_set_parent(text2b, hsplit_text2);
    gui_set_align(text2b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    if (strlen(derivation) > 20) {
        gui_set_text_scroll(text2b, TFT_BLACK);
    }

    gui_view_node_t* hsplit_text3;
    gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text3, vsplit);

    gui_view_node_t* text3a;
    gui_make_text(&text3a, "Xpub", TFT_WHITE);
    gui_set_parent(text3a, hsplit_text3);
    gui_set_align(text3a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* text3b;
    gui_make_text(&text3b, signer->xpub, TFT_WHITE);
    gui_set_parent(text3b, hsplit_text3);
    gui_set_align(text3b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text3b, TFT_BLACK);

    gui_view_node_t* hsplit_text4;
    gui_make_hsplit(&hsplit_text4, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text4, vsplit);

    gui_view_node_t* text4a;
    gui_make_text(&text4a, "Path", TFT_WHITE);
    gui_set_parent(text4a, hsplit_text4);
    gui_set_align(text4a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    char path[128];
    if (signer->path_len == 0) {
        strcpy(path, "None");
    } else if (!bip32_path_as_str(signer->path, signer->path_len, path, sizeof(path))) {
        strcpy(path, "[too long]");
    }

    gui_view_node_t* text4b;
    gui_make_text(&text4b, path, TFT_WHITE);
    gui_set_parent(text4b, hsplit_text4);
    gui_set_align(text4b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    if (strlen(path) > 20) {
        gui_set_text_scroll(text4b, TFT_BLACK);
    }

    // Buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    // [<-] [X] [->]  (Prev, cancel, next)
    gui_view_node_t* btn1 = NULL;
    gui_make_button(&btn1, TFT_BLACK, BTN_MULTISIG_PREV, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "=", TFT_WHITE);
    gui_set_text_font(textbtn1, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_MULTISIG_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, hsplit_btn);

    gui_view_node_t* textbtn2;
    gui_make_text(&textbtn2, "X", TFT_WHITE);
    gui_set_parent(textbtn2, btn2);
    gui_set_align(textbtn2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_MULTISIG_NEXT, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text(&textbtn3, ">", TFT_WHITE);
    gui_set_text_font(textbtn3, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Connect every screen's 'exit' button to the 'translate' handler above
    gui_activity_register_event(act, GUI_BUTTON_EVENT, BTN_MULTISIG_EXIT, translate_event, NULL);

    // Set the intially selected item to the 'Next' button (ie. btn3)
    gui_set_activity_initial_selection(act, btn3);

    // Push details into the output structure
    link_activity->activity = act;
    link_activity->prev_button = btn1;
    link_activity->next_button = btn3;
}

static void make_final_confirm_screen(link_activity_t* link_activity, const char* multisig_name, const size_t threshold,
    const size_t num_signers, const bool overwriting)
{
    JADE_ASSERT(link_activity);
    JADE_ASSERT(multisig_name);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Confirm Multisig");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text1;
    gui_make_text(&text1, "Register this multisig?", TFT_WHITE);
    gui_set_parent(text1, vsplit);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2a;
    gui_make_text(&text2a, "Name", TFT_WHITE);
    gui_set_parent(text2a, hsplit_text2);
    gui_set_align(text2a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* text2b;
    gui_make_text(&text2b, multisig_name, TFT_WHITE);
    gui_set_parent(text2b, hsplit_text2);
    gui_set_align(text2b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* hsplit_text3;
    gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text3, vsplit);

    gui_view_node_t* text3a;
    gui_make_text(&text3a, "Type", TFT_WHITE);
    gui_set_parent(text3a, hsplit_text3);
    gui_set_align(text3a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    char type[16];
    int ret = snprintf(type, sizeof(type), "%uof%u", threshold, num_signers);
    JADE_ASSERT(ret > 0 && ret < sizeof(type));

    gui_view_node_t* text3b;
    gui_make_text(&text3b, type, TFT_WHITE);
    gui_set_parent(text3b, hsplit_text3);
    gui_set_align(text3b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    // Show warning if overwriting
    if (overwriting) {
        gui_view_node_t* text4;
        gui_make_text(&text4, "Warning: overwriting existing registration", TFT_RED);
        gui_set_parent(text4, vsplit);
        gui_set_align(text4, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text4, TFT_BLACK);
    } else {
        gui_view_node_t* row4;
        gui_make_fill(&row4, TFT_BLACK);
        gui_set_parent(row4, vsplit);
    }

    // Buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    // [<-] [X] [V]  (Prev, cancel, confirm)
    gui_view_node_t* btn1 = NULL;
    gui_make_button(&btn1, TFT_BLACK, BTN_MULTISIG_PREV, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "=", TFT_WHITE);
    gui_set_text_font(textbtn1, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_MULTISIG_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, hsplit_btn);

    gui_view_node_t* textbtn2;
    gui_make_text(&textbtn2, "X", TFT_WHITE);
    gui_set_parent(textbtn2, btn2);
    gui_set_align(textbtn2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_MULTISIG_CONFIRM, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text(&textbtn3, "S", TFT_WHITE);
    gui_set_text_font(textbtn3, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Connect every screen's 'exit' button to the 'translate' handler above
    gui_activity_register_event(act, GUI_BUTTON_EVENT, BTN_MULTISIG_EXIT, translate_event, NULL);

    // Connect the ''confirm' button to the 'translate' handler above too
    gui_activity_register_event(act, GUI_BUTTON_EVENT, BTN_MULTISIG_CONFIRM, translate_event, NULL);

    // Set the intially selected item to the 'No' button (ie. btn2)
    gui_set_activity_initial_selection(act, btn2);

    // Push details into the output structure
    link_activity->activity = act;
    link_activity->prev_button = btn1;
    link_activity->next_button = NULL;
}

void make_confirm_multisig_activity(const char* multisig_name, const bool sorted, const size_t threshold,
    const signer_t* signers, const size_t num_signers, const uint8_t* wallet_fingerprint,
    const size_t wallet_fingerprint_len, const bool overwriting, gui_activity_t** first_activity)
{
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(threshold > 0);
    JADE_ASSERT(signers);
    JADE_ASSERT(num_signers >= threshold);
    JADE_ASSERT(wallet_fingerprint);
    JADE_ASSERT(wallet_fingerprint_len == BIP32_KEY_FINGERPRINT_LEN);
    JADE_ASSERT(first_activity);

    // Track the first and last activities created
    link_activity_t link_act;
    linked_activities_info_t act_info
        = { .first_activity = NULL, .last_activity = NULL, .last_activity_next_button = NULL };

    // 1 based indices for display purposes
    make_initial_confirm_screen(
        &link_act, multisig_name, sorted, threshold, num_signers, wallet_fingerprint, wallet_fingerprint_len);
    gui_chain_activities(&link_act, &act_info);

    // Screen per signer
    for (size_t i = 0; i < num_signers; ++i) {
        const signer_t* signer = signers + i;
        const bool is_this_wallet = sodium_memcmp(signer->fingerprint, wallet_fingerprint, wallet_fingerprint_len) == 0;
        make_signer_activity(&link_act, num_signers, i + 1, is_this_wallet, signer);
        gui_chain_activities(&link_act, &act_info);
    }

    // Final confirmation
    make_final_confirm_screen(&link_act, multisig_name, threshold, num_signers, overwriting);
    gui_chain_activities(&link_act, &act_info);

    // Set output param
    *first_activity = act_info.first_activity;
}

void make_view_multisig_activity(gui_activity_t** activity, const char* multisig_name, const size_t index,
    const size_t total, const bool valid, const bool sorted, const size_t threshold, const size_t num_signers)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(multisig_name);

    gui_activity_t* act;
    char header[24];
    const int ret = snprintf(header, sizeof(header), "Multisig %d/%d", index, total);
    JADE_ASSERT(ret > 0 && ret < sizeof(header));
    gui_make_activity(&act, true, header);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* text1;
    gui_make_text(&text1, "Mustisig Registration:", TFT_WHITE);
    gui_set_parent(text1, vsplit);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 25, 75);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2a;
    gui_make_text(&text2a, "Name", TFT_WHITE);
    gui_set_parent(text2a, hsplit_text2);
    gui_set_align(text2a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    gui_view_node_t* text2b;
    gui_make_text(&text2b, multisig_name, TFT_WHITE);
    gui_set_parent(text2b, hsplit_text2);
    gui_set_align(text2b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    if (valid) {
        gui_view_node_t* hsplit_text3;
        gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_set_parent(hsplit_text3, vsplit);

        char type[16];
        int ret = snprintf(type, sizeof(type), "%uof%u", threshold, num_signers);
        JADE_ASSERT(ret > 0 && ret < sizeof(type));

        gui_view_node_t* text3a;
        gui_make_text(&text3a, "Type", TFT_WHITE);
        gui_set_parent(text3a, hsplit_text3);
        gui_set_align(text3a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text3b;
        gui_make_text(&text3b, type, TFT_WHITE);
        gui_set_parent(text3b, hsplit_text3);
        gui_set_align(text3b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* hsplit_text4;
        gui_make_hsplit(&hsplit_text4, GUI_SPLIT_RELATIVE, 2, 25, 75);
        gui_set_parent(hsplit_text4, vsplit);

        gui_view_node_t* text4a;
        gui_make_text(&text4a, "Sorted", TFT_WHITE);
        gui_set_parent(text4a, hsplit_text4);
        gui_set_align(text4a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text4b;
        gui_make_text(&text4b, sorted ? "Y" : "N", TFT_WHITE);
        gui_set_parent(text4b, hsplit_text4);
        gui_set_align(text4b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    } else {
        // Not valid for this wallet - just show warning
        gui_view_node_t* text3;
        gui_make_text(&text3, "Not valid for this wallet", TFT_RED);
        gui_set_parent(text3, vsplit);
        gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* row4;
        gui_make_fill(&row4, TFT_BLACK);
        gui_set_parent(row4, vsplit);
    }

    // Buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    // Delete/Next
    gui_view_node_t* btn1 = NULL;
    gui_make_button(&btn1, TFT_BLACK, BTN_MULTISIG_DELETE, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "Delete", TFT_WHITE);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    const bool has_next = index < total;
    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, has_next ? BTN_MULTISIG_NEXT : BTN_MULTISIG_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, hsplit_btn);

    gui_view_node_t* textbtn2;
    if (has_next) {
        gui_make_text(&textbtn2, ">", TFT_WHITE);
        gui_set_text_font(textbtn2, JADE_SYMBOLS_16x16_FONT);
    } else {
        gui_make_text(&textbtn2, "Exit", TFT_WHITE);
    }
    gui_set_parent(textbtn2, btn2);
    gui_set_align(textbtn2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Set the intially selected item to the 'Next' button (ie. btn2)
    gui_set_activity_initial_selection(act, btn2);

    *activity = act;
}
