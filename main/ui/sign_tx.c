#include <assets.h>
#include <inttypes.h>
#include <math.h>
#include <wally_transaction.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../ui.h"
#include "../utils/address.h"
#include "../utils/event.h"

typedef struct {
    gui_activity_t* activity;
    gui_view_node_t* prev_button;
    gui_view_node_t* next_button;
} output_activity_t;

typedef struct {
    gui_activity_t* first_activity;
    gui_activity_t* last_activity;
    gui_view_node_t* last_activity_next_button;
} activities_info_t;

// A warning to display if the asset registry data is missing
static const char MISSING_ASSET_DATA[] = "Amounts may be expressed in the wrong units. Proceed at your own risk.";

// Translate a GUI button (ok/cancel) into a sign_tx_ JADE_EVENT (so the caller
// can await without worrying about which screen/activity it came from).
static void translate_event(void* handler_arg, esp_event_base_t base, int32_t id, void* unused)
{
    JADE_ASSERT(id == BTN_TX_SCREEN_EXIT || id == BTN_TX_SCREEN_NEXT);
    esp_event_post(JADE_EVENT, id == BTN_TX_SCREEN_NEXT ? SIGN_TX_ACCEPT_OUTPUTS : SIGN_TX_DECLINE, NULL, 0,
        100 / portTICK_PERIOD_MS);
}

// Helper to make a screen activity to display an output for the user to verify.
// Displays destination address, passed amount (already formatted for display),
// and the associated ticker if one is passed.
//
// It can also display one of:
// a) Asset string (eg. issuer + asset-id) for liquid registered assets, or
// b) any warning message that may be associated with this output.
//
// Due to screen real-estate / visual overcrowding issues it was decided that liquid
// outputs that have both asset data *and* a warning message would be displayed twice
// (once with the warning, and again with the asset info) rather than trying to squeeze
// all the information onto the screen a once.
//
// So it is not valid to call this with both asset_str and warning_msg.
//
static void make_output_activity(output_activity_t* output_activity, const bool want_prev_btn, uint32_t index,
    uint32_t total, const char* address, const char* amount, const char* ticker, const char* asset_str,
    const char* warning_msg)
{
    JADE_ASSERT(output_activity);
    JADE_ASSERT(address);
    JADE_ASSERT(amount);
    JADE_ASSERT(!asset_str || !warning_msg);

    gui_activity_t* act;
    char header[16];
    const int ret = snprintf(header, sizeof(header), "Output %d/%d", index, total);
    JADE_ASSERT(ret > 0 && ret < sizeof(header));
    gui_make_activity(&act, true, header);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 5, 17, 17, 17, 17, 32);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* row1;
    gui_make_fill(&row1, TFT_BLACK);
    gui_set_parent(row1, vsplit);

    gui_view_node_t* hsplit_text1;
    gui_make_hsplit(&hsplit_text1, GUI_SPLIT_RELATIVE, 2, 15, 85);
    gui_set_parent(hsplit_text1, row1);

    gui_view_node_t* text1a;
    gui_make_text(&text1a, "To", TFT_WHITE);
    gui_set_parent(text1a, hsplit_text1);
    gui_set_align(text1a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text1a, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    gui_view_node_t* text1b;
    gui_make_text(&text1b, address, TFT_WHITE);
    gui_set_parent(text1b, hsplit_text1);
    gui_set_align(text1b, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text1b, TFT_BLACK);

    gui_view_node_t* row2;
    gui_make_fill(&row2, TFT_BLACK);
    gui_set_parent(row2, vsplit);

    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 70, 30);
    gui_set_parent(hsplit_text2, row2);

    gui_view_node_t* text2a;
    gui_make_text(&text2a, amount, TFT_WHITE);
    gui_set_parent(text2a, hsplit_text2);
    gui_set_align(text2a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    if (ticker) {
        gui_view_node_t* text2b;
        gui_make_text(&text2b, ticker, TFT_WHITE);
        gui_set_parent(text2b, hsplit_text2);
        gui_set_align(text2b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        gui_set_borders(text2b, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);
    }

    gui_view_node_t* row3;
    gui_make_fill(&row3, TFT_BLACK);
    gui_set_parent(row3, vsplit);

    gui_view_node_t* row4;
    gui_make_fill(&row4, TFT_BLACK);
    gui_set_parent(row4, vsplit);

    // If 'warning_msg' - then show the message.
    // Otherwise show the asset string (issuer, id, etc)
    if (warning_msg) {
        JADE_ASSERT(!asset_str);

        gui_view_node_t* text3;
        gui_make_text(&text3, "Warning:", TFT_RED);
        gui_set_parent(text3, row3);
        gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text3, TFT_BLACK);

        gui_view_node_t* text4;
        gui_make_text(&text4, warning_msg, TFT_RED);
        gui_set_parent(text4, row4);
        gui_set_align(text4, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text4, TFT_BLACK);
    } else if (asset_str) {
        gui_view_node_t* hsplit_text3;
        gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 30, 70);
        gui_set_parent(hsplit_text3, row3);

        gui_view_node_t* text3a;
        gui_make_text(&text3a, "Asset", TFT_WHITE);
        gui_set_parent(text3a, hsplit_text3);
        gui_set_align(text3a, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        gui_view_node_t* text3b;
        gui_make_text(&text3b, asset_str, TFT_WHITE);
        gui_set_parent(text3b, hsplit_text3);
        gui_set_align(text3b, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text3b, TFT_BLACK);

        // row4 is blank
    }

    // Buttons
    gui_view_node_t* row5;
    gui_make_fill(&row5, TFT_BLACK);
    gui_set_parent(row5, vsplit);

    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, row5);

    // If we want a prev btn, add it here.  If not just add filler.
    gui_view_node_t* btn1 = NULL;
    if (want_prev_btn) {
        gui_make_button(&btn1, TFT_BLACK, BTN_TX_SCREEN_PREV, NULL);
        gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
        gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
        gui_set_parent(btn1, hsplit_btn);

        gui_view_node_t* textbtn1;
        gui_make_text(&textbtn1, "=", TFT_WHITE);
        gui_set_text_font(textbtn1, JADE_SYMBOLS_16x16_FONT);
        gui_set_parent(textbtn1, btn1);
        gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    } else {
        gui_view_node_t* filler;
        gui_make_fill(&filler, TFT_BLACK);
        gui_set_parent(filler, hsplit_btn);
    }

    gui_view_node_t* btn2;
    gui_make_button(&btn2, TFT_BLACK, BTN_TX_SCREEN_EXIT, NULL);
    gui_set_margins(btn2, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn2, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn2, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn2, hsplit_btn);

    gui_view_node_t* textbtn2;
    gui_make_text(&textbtn2, "X", TFT_WHITE);
    gui_set_parent(textbtn2, btn2);
    gui_set_align(textbtn2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_TX_SCREEN_NEXT, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text(&textbtn3, "S", TFT_WHITE);
    gui_set_text_font(textbtn3, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    // Set the intially selected item to the 'Next' button (ie. btn3)
    gui_set_activity_initial_selection(act, btn3);

    // Push details into the output structure
    output_activity->activity = act;
    output_activity->prev_button = btn1;
    output_activity->next_button = btn3;
}

static void make_final_activity(
    gui_activity_t** activity, const char* total_fee, const char* ticker, const char* warning_msg)
{
    JADE_ASSERT(activity);

    gui_activity_t* act;
    gui_make_activity(&act, true, "Summary");

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, act->root_node);

    gui_view_node_t* bg1;
    gui_make_fill(&bg1, TFT_BLACK);
    gui_set_parent(bg1, vsplit);

    gui_view_node_t* hsplit_text1;
    gui_make_hsplit(&hsplit_text1, GUI_SPLIT_RELATIVE, 2, 20, 80);
    gui_set_parent(hsplit_text1, bg1);

    gui_view_node_t* text1;
    gui_make_text(&text1, "Fee", TFT_WHITE);
    gui_set_parent(text1, hsplit_text1);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text1, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    gui_view_node_t* text1b;
    char tx_fees[32];
    const int ret = snprintf(tx_fees, sizeof(tx_fees), "%s %s", total_fee, ticker);
    JADE_ASSERT(ret > 0 && ret < sizeof(tx_fees));
    gui_make_text(&text1b, tx_fees, TFT_WHITE);
    gui_set_parent(text1b, hsplit_text1);
    gui_set_align(text1b, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);

    // Show any warning message
    gui_view_node_t* bg2;
    gui_make_fill(&bg2, TFT_BLACK);
    gui_set_parent(bg2, vsplit);
    gui_view_node_t* bg3;
    gui_make_fill(&bg3, TFT_BLACK);
    gui_set_parent(bg3, vsplit);

    if (warning_msg) {
        gui_view_node_t* text2;
        gui_make_text(&text2, "Warning:", TFT_RED);
        gui_set_parent(text2, bg2);
        gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text2, TFT_BLACK);

        gui_view_node_t* text3;
        gui_make_text(&text3, warning_msg, TFT_RED);
        gui_set_parent(text3, bg3);
        gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_text_scroll(text3, TFT_BLACK);
    }

    gui_view_node_t* bg4;
    gui_make_fill(&bg4, TFT_BLACK);
    gui_set_parent(bg4, vsplit);

    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, bg4);

    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_CANCEL_SIGNATURE, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "X", TFT_WHITE);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* black_fill;
    gui_make_fill(&black_fill, TFT_BLACK);
    gui_set_parent(black_fill, hsplit_btn);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_ACCEPT_SIGNATURE, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text(&textbtn3, "S", TFT_WHITE);
    gui_set_text_font(textbtn3, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    *activity = act;
}

// Don't display pre-validated (eg. change) outputs (if provided)
// Should work for elements and standard btc, but liquid hides scriptless outputs (fees)
static inline bool display_output(
    const struct wally_tx_output* outputs, const output_info_t* output_info, const size_t i, const bool show_scriptless)
{
    return (show_scriptless || outputs[i].script) && !(output_info && output_info[i].is_validated_change_address);
}

static uint32_t displayable_outputs(
    const struct wally_tx* tx, const output_info_t* output_info, const bool show_scriptless)
{
    uint32_t nDisplayable = 0;
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        if (display_output(tx->outputs, output_info, i, show_scriptless)) {
            ++nDisplayable;
        }
    }

    // If we would hide all outputs, then don't hide any
    return nDisplayable > 0 ? nDisplayable : tx->num_outputs;
}

// Helper to call to create screen for single output
static void make_single_output_screen(activities_info_t* pActInfo, uint32_t index, uint32_t total, const char* address,
    const char* amount, const char* ticker, const char* asset_str, const char* warning_msg)
{
    JADE_ASSERT(pActInfo);

    output_activity_t output_act;
    make_output_activity(
        &output_act, pActInfo->last_activity, index, total, address, amount, ticker, asset_str, warning_msg);
    JADE_ASSERT(output_act.activity);

    // Connect every screen's 'exit' button to the 'translate' handler above
    gui_activity_register_event(output_act.activity, GUI_BUTTON_EVENT, BTN_TX_SCREEN_EXIT, translate_event, NULL);

    // Record the first activity
    if (!pActInfo->first_activity) {
        pActInfo->first_activity = output_act.activity;
    }

    // Link activities together by prev and next buttons
    if (pActInfo->last_activity) {
        // connect our "prev" btn to prev activity
        JADE_ASSERT(output_act.prev_button);
        gui_connect_button_activity(output_act.prev_button, pActInfo->last_activity);

        // connect prev "next" btn to this activity
        JADE_ASSERT(pActInfo->last_activity_next_button);
        gui_connect_button_activity(pActInfo->last_activity_next_button, output_act.activity);
    }

    // Update 'last activity' information to this new activity
    pActInfo->last_activity = output_act.activity;
    pActInfo->last_activity_next_button = output_act.next_button;
}

void make_display_output_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info, gui_activity_t** first_activity)
{
    // Note: outputs_validated is optional and can be null
    JADE_ASSERT(tx);
    JADE_ASSERT(first_activity);

    // Show outputs which don't have a script
    const bool show_scriptless = true;

    // Track the first and last activities created
    activities_info_t act_info = { .first_activity = NULL, .last_activity = NULL, .last_activity_next_button = NULL };

    // 1 based indices for display purposes
    uint32_t nDisplayedOutput = 0;
    const uint32_t nTotalOutputsDisplayed = displayable_outputs(tx, output_info, show_scriptless);
    const bool hiddenOutputs = nTotalOutputsDisplayed < tx->num_outputs;

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        struct wally_tx_output* out = tx->outputs + i;

        // Skip outputs we have automatically validated (eg. change outputs)
        if (hiddenOutputs && !display_output(tx->outputs, output_info, i, show_scriptless)) {
            continue;
        }

        char amount[32];
        int ret = snprintf(amount, sizeof(amount), "%.08f", 1.0 * out->satoshi / 1e8);
        JADE_ASSERT(ret > 0 && ret < sizeof(amount));

        char address[MAX_ADDRESS_LEN];
        script_to_address(network, out->script, out->script_len, address, sizeof(address));

        char display_address[MAX_ADDRESS_LEN + 4];
        ret = snprintf(display_address, sizeof(display_address), "} %s {", address);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_address));

        const char* msg = output_info && strlen(output_info[i].message) > 0 ? output_info[i].message : NULL;

        ++nDisplayedOutput;
        make_single_output_screen(
            &act_info, nDisplayedOutput, nTotalOutputsDisplayed, display_address, amount, "BTC", NULL, msg);
    }
    JADE_ASSERT(nDisplayedOutput == nTotalOutputsDisplayed);

    // Connect the final screen's 'next' button to the 'translate' handler above
    gui_activity_register_event(act_info.last_activity, GUI_BUTTON_EVENT, BTN_TX_SCREEN_NEXT, translate_event, NULL);

    *first_activity = act_info.first_activity;
}

void make_display_elements_output_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info, gui_activity_t** first_activity)
{
    JADE_ASSERT(tx);
    JADE_ASSERT(output_info);
    JADE_ASSERT(first_activity);

    // Don't show outputs which don't have a script (as these are fees)
    const bool show_scriptless = false;

    // Track the first and last activities created
    activities_info_t act_info = { .first_activity = NULL, .last_activity = NULL, .last_activity_next_button = NULL };

    // 1 based indices for display purposes
    uint32_t nDisplayedOutput = 0;
    const uint32_t nTotalOutputsDisplayed = displayable_outputs(tx, output_info, show_scriptless);
    const bool hiddenOutputs = nTotalOutputsDisplayed < tx->num_outputs;

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        struct wally_tx_output* out = tx->outputs + i;

        // Skip outputs we have automatically validated (eg. change outputs)
        // also, skip/hide fees (ie. outputs sans script)
        if (hiddenOutputs && !display_output(tx->outputs, output_info, i, show_scriptless)) {
            continue;
        }

        // Get the asset-id display hex string
        unsigned char flipped_asset_id[32];
        for (size_t x = 0; x < 32; x++) {
            flipped_asset_id[x] = output_info[i].asset_id[32 - x - 1];
        }

        char* asset_id_hex = NULL;
        JADE_WALLY_VERIFY(wally_hex_from_bytes(flipped_asset_id, 32, &asset_id_hex));
        JADE_ASSERT(asset_id_hex);

        // Look up the asset-id in the canned asset-data
        const char* ticker = NULL;
        const char* issuer = NULL;
        const asset_info_t* const pInfo = assets_get_info(asset_id_hex);
        if (pInfo) {
            JADE_LOGD("Found asset data for output %u (asset-id: '%s')", i, asset_id_hex);
            JADE_ASSERT(!strcmp(asset_id_hex, pInfo->asset_id));
            ticker = pInfo->ticker;
            issuer = pInfo->issuer_domain;
        } else {
            JADE_LOGW("Asset data for output %u (asset-id: '%s') not found!", i, asset_id_hex);
        }

        if (!issuer || strlen(issuer) == 0) {
            issuer = "issuer unknown";
        }

        char asset_str[128];
        int ret = snprintf(asset_str, sizeof(asset_str), "} %s - %s {", issuer, asset_id_hex);
        JADE_ASSERT(ret > 0 && ret < sizeof(asset_str));
        wally_free_string(asset_id_hex);

        char amount[32];
        const int precision = pInfo ? pInfo->precision : 0;
        JADE_ASSERT(precision < 10);
        const uint32_t scale_factor = pow(10, precision);

        char fmt[8];
        ret = snprintf(fmt, sizeof(fmt), "%%.%02uf", precision);
        JADE_ASSERT(ret > 0 && ret < sizeof(fmt));
        ret = snprintf(amount, sizeof(amount), fmt, 1.0 * output_info[i].value / scale_factor);
        JADE_ASSERT(ret > 0 && ret < sizeof(amount));

        char address[MAX_ADDRESS_LEN];
        elements_script_to_address(network, out->script, out->script_len,
            output_info[i].is_confidential ? output_info[i].blinding_key : NULL, sizeof(output_info[i].blinding_key),
            address, sizeof(address));

        char display_address[MAX_ADDRESS_LEN + 4];
        ret = snprintf(display_address, sizeof(display_address), "} %s {", address);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_address));

        ++nDisplayedOutput;

        // Insert extra screen to display warning message for this output, if one is passed
        if (strlen(output_info[i].message) > 0) {
            // Make activity with no asset-id but with the warning message
            make_single_output_screen(&act_info, nDisplayedOutput, nTotalOutputsDisplayed, display_address, amount,
                ticker, NULL, output_info[i].message);
        }

        // Insert extra screen to display warning if the asset registry information is missing
        if (!pInfo) {
            // Make activity with no asset-id but with the warning message
            make_single_output_screen(&act_info, nDisplayedOutput, nTotalOutputsDisplayed, display_address, amount,
                ticker, NULL, MISSING_ASSET_DATA);
        }

        // Normal output screen - with issuer and asset-id but no warning message
        make_single_output_screen(
            &act_info, nDisplayedOutput, nTotalOutputsDisplayed, display_address, amount, ticker, asset_str, NULL);
    }
    JADE_ASSERT(nDisplayedOutput == nTotalOutputsDisplayed);

    // Connect the final screen's 'next' button to the 'translate' handler above
    gui_activity_register_event(act_info.last_activity, GUI_BUTTON_EVENT, BTN_TX_SCREEN_NEXT, translate_event, NULL);

    // Set output parameters
    *first_activity = act_info.first_activity;
}

void make_display_final_confirmation_activity(const uint64_t fee, const char* warning_msg, gui_activity_t** activity)
{
    JADE_ASSERT(activity);

    char fee_str[32];
    const int ret = snprintf(fee_str, sizeof(fee_str), "%.08f", 1.0 * fee / 1e8);
    JADE_ASSERT(ret > 0 && ret < sizeof(fee_str));

    // final confirmation screen
    make_final_activity(activity, fee_str, "BTC", warning_msg);
    JADE_ASSERT(*activity);
}

void make_display_elements_final_confirmation_activity(
    const uint64_t fee, const char* warning_msg, gui_activity_t** activity)
{
    JADE_ASSERT(activity);

    char fee_str[32];
    const int ret = snprintf(fee_str, sizeof(fee_str), "%.08f", 1.0 * fee / 1e8);
    JADE_ASSERT(ret > 0 && ret < sizeof(fee_str));

    // final confirmation screen
    make_final_activity(activity, fee_str, "L-BTC", warning_msg);
    JADE_ASSERT(*activity);
}
