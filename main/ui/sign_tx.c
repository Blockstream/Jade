#include <assets_snapshot.h>
#include <inttypes.h>
#include <math.h>
#include <wally_elements.h>
#include <wally_transaction.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../ui.h"
#include "../utils/address.h"
#include "../utils/event.h"
#include "../utils/network.h"
#include "../utils/util.h"

// from confirm_address
gui_activity_t* make_display_address_activities(const char* title, bool show_one_screen_tick, const char* address,
    bool default_selection, gui_activity_t** actaddr2);

// A warning to display if the asset registry data is missing
static const char MISSING_ASSET_DATA[] = "Amounts may be shown in the wrong units.      Continue at your own   risk.";

// A warning to display if the unblinding data is missing
static const char BLINDED_OUTPUT[] = "Cannot unblind output";

// Note shown to highlight outputs to self (script/address verified)
static const char VERIFIED_WALLET_OUTPUT_MSG[] = "Verified wallet output";

static const char TICKER_BTC[] = "BTC";

// Don't display pre-validated (eg. change) outputs (if provided) unless they have an associated warning message.
// Should work for elements and standard btc, but liquid hides scriptless outputs (fees)
static bool display_output(
    const struct wally_tx_output* outputs, const output_info_t* output_info, const size_t i, const bool show_scriptless)
{
    if (!show_scriptless && !outputs[i].script) {
        // Hide outputs with no script
        return false;
    }

    if (output_info) {
        if (output_info[i].message[0] != '\0') {
            // Show outputs that have an associated warning message
            return true;
        }

        if (output_info[i].flags & OUTPUT_FLAG_VALIDATED && output_info[i].flags & OUTPUT_FLAG_CHANGE) {
            // Hide change outputs which have already been internally validated
            return false;
        }
    }

    // No reason to hide this output
    return true;
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

// Lookup the passed asset-id in the asset data, and return the asset-id, issuer,
// ticker, and the passed value scaled correctly for the precision provided.
static bool get_asset_display_info(const char* network, const asset_info_t* assets, const size_t num_assets,
    const uint8_t* asset_id, const size_t asset_id_len, const uint64_t value, char* issuer, const size_t issuer_len,
    char* asset_id_hex, const size_t asset_id_hex_len, char* amount, const size_t amount_len, char* ticker,
    const size_t ticker_len)
{
    JADE_ASSERT(network);
    JADE_ASSERT(assets || !num_assets);
    JADE_ASSERT(asset_id);
    JADE_ASSERT(asset_id_len);
    JADE_ASSERT(issuer);
    JADE_ASSERT(issuer_len);
    JADE_ASSERT(asset_id_hex);
    JADE_ASSERT(asset_id_hex_len);
    JADE_ASSERT(amount);
    JADE_ASSERT(amount_len);
    JADE_ASSERT(ticker);
    JADE_ASSERT(ticker_len);

    // Get the asset-id display hex string
    char* idhex = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(asset_id, asset_id_len, &idhex));
    JADE_ASSERT(idhex);
    int ret = snprintf(asset_id_hex, asset_id_hex_len, "%s", idhex);
    JADE_ASSERT(ret > 0 && ret < asset_id_hex_len);
    JADE_WALLY_VERIFY(wally_free_string(idhex));

    // Look up the asset-id in the canned asset-data
    asset_info_t asset_info = {};
    const bool have_asset_info = assets_get_info(network, assets, num_assets, asset_id_hex, &asset_info);
    if (have_asset_info) {
        JADE_LOGI("Found asset data for asset-id: '%s'", asset_id_hex);

        // Issuer - truncate if overlong
        ret = snprintf(issuer, issuer_len, "%.*s", asset_info.issuer_domain_len, asset_info.issuer_domain);
        JADE_ASSERT(ret > 0);
        if (ret >= issuer_len) {
            issuer[issuer_len - 4] = '.';
            issuer[issuer_len - 3] = '.';
            issuer[issuer_len - 2] = '.';
            issuer[issuer_len - 1] = '\0';
        }

        // Amount scaled and displayed at relevant precision
        const uint32_t scale_factor = pow(10, asset_info.precision);
        ret = snprintf(amount, amount_len, "%.*f", asset_info.precision, 1.0 * value / scale_factor);
        JADE_ASSERT(ret > 0 && ret < amount_len);

        // Ticker
        ret = snprintf(ticker, ticker_len, "%.*s", asset_info.ticker_len, asset_info.ticker);
        JADE_ASSERT(ret > 0 && ret < ticker_len);
    } else {
        JADE_LOGW("Asset data for asset-id: '%s' not found!", asset_id_hex);

        // Issuer unknown
        ret = snprintf(issuer, issuer_len, "%s", make_empty_none(NULL));
        JADE_ASSERT(ret > 0 && ret < issuer_len);

        // sats precision
        ret = snprintf(amount, amount_len, "%.00f", 1.0 * value);
        JADE_ASSERT(ret > 0 && ret < amount_len);

        // No ticker
        ret = snprintf(ticker, ticker_len, "%s", make_empty_none(NULL));
        JADE_ASSERT(ret > 0 && ret < ticker_len);
    }

    return have_asset_info;
}

static gui_activity_t* make_display_assetinfo_activities(
    const char* ticker, const char* issuer, const char* asset_id_hex, gui_activity_t** assetinfo2)
{
    JADE_ASSERT(ticker);
    JADE_ASSERT(issuer);
    JADE_ASSERT(asset_id_hex);
    JADE_INIT_OUT_PPTR(assetinfo2);

    // Need two screens to show asset info
    char buf[128];
    const char* message[] = { buf };

    // First screen, ticker and issuer
    btn_data_t hdrbtns1[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNTX_ASSETINFO_DONE },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNTX_ASSETINFO_NEXT } };

    int ret = snprintf(buf, sizeof(buf), "\n%s\n%s", ticker, issuer);
    JADE_ASSERT(ret > 0);
    if (ret > sizeof(buf)) {
        buf[sizeof(buf) - 4] = '.';
        buf[sizeof(buf) - 3] = '.';
        buf[sizeof(buf) - 2] = '.';
        buf[sizeof(buf) - 1] = '\0';
    }

    gui_activity_t* const act = make_show_message_activity(message, 1, "Asset Info", hdrbtns1, 2, NULL, 0);

    gui_set_activity_initial_selection(act, hdrbtns1[1].btn);

    // Second screen, asset id hex
    ret = snprintf(buf, sizeof(buf), "\n%s", asset_id_hex);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf));

    btn_data_t hdrbtns2[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNTX_ASSETINFO_NEXT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_SIGNTX_ASSETINFO_DONE } };

    *assetinfo2 = make_show_message_activity(message, 1, "Asset Id", hdrbtns2, 2, NULL, 0);

    gui_set_activity_initial_selection(*assetinfo2, hdrbtns2[1].btn);

    return act;
}

static gui_activity_t* make_input_output_activities(const char* title, const bool is_wallet_output,
    const bool is_address, const char* address_label, const char* amount, const char* ticker, const char* issuer,
    const char* asset_id_hex, const char* warning_msg, gui_activity_t** acttickeramt, gui_activity_t** actaddr1,
    gui_activity_t** actaddr2, gui_activity_t** actassetinfo1, gui_activity_t** actassetinfo2,
    gui_activity_t** actwarning)
{
    JADE_ASSERT(title);
    JADE_ASSERT(address_label);
    JADE_ASSERT(amount);
    JADE_ASSERT(ticker);
    // asset info is both or neither
    JADE_ASSERT(asset_id_hex);
    JADE_ASSERT(!issuer == !strlen(asset_id_hex));
    // warning_msg is optional
    JADE_INIT_OUT_PPTR(acttickeramt);
    JADE_INIT_OUT_PPTR(actaddr1);
    JADE_INIT_OUT_PPTR(actaddr2);
    JADE_INIT_OUT_PPTR(actassetinfo1);
    JADE_INIT_OUT_PPTR(actassetinfo2);
    JADE_INIT_OUT_PPTR(actwarning);

    char display_str[128];
    const bool show_help_btn = false;
    gui_view_node_t* node;

    // First row, address
    gui_view_node_t* splitaddr;
    gui_view_node_t* addr;

    if (is_address) {
        // Address, show as 'To: <addr>'
        gui_make_hsplit(&splitaddr, GUI_SPLIT_RELATIVE, 2, 20, 80);

        gui_make_text(&addr, "To: ", TFT_WHITE);
        gui_set_align(addr, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        gui_set_parent(addr, splitaddr);

        gui_make_text(&addr, address_label, TFT_WHITE);
        gui_set_align(addr, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(addr, splitaddr);
    } else {
        // Simple label, show as '<label>' (centered)
        gui_make_text(&addr, address_label, TFT_WHITE);
        gui_set_align(addr, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        splitaddr = addr;
    }

    const bool show_tick = false;
    const bool default_selection = true;
    const char* addr_label_title = is_address ? "To Address" : "Description";
    *actaddr1
        = make_display_address_activities(addr_label_title, show_tick, address_label, default_selection, actaddr2);

    // Second row, amount + ticker
    gui_view_node_t* splitamount;
    gui_make_hsplit(&splitamount, GUI_SPLIT_RELATIVE, 2, 65, 35);

    gui_view_node_t* amountvalue;
    gui_make_text(&amountvalue, amount, TFT_WHITE);
    gui_set_align(amountvalue, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(amountvalue, splitamount);

    gui_make_text(&node, ticker, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, splitamount);

    int ret = snprintf(display_str, sizeof(display_str), "%s\n%s", amount, ticker);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    *acttickeramt = make_show_single_value_activity("Amount", display_str, show_help_btn);

    // Third row, asset-info
    gui_view_node_t* assetinfo = NULL;
    if (issuer) {
        ret = snprintf(display_str, sizeof(display_str), "%s - %s", issuer, asset_id_hex);
        JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

        gui_make_text(&assetinfo, display_str, TFT_WHITE);
        gui_set_align(assetinfo, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        *actassetinfo1 = make_display_assetinfo_activities(ticker, issuer, asset_id_hex, actassetinfo2);
    }

    // Fourth row, warning
    gui_view_node_t* warning = NULL;
    if (warning_msg) {
        gui_make_text(&warning, warning_msg, TFT_WHITE);
        gui_set_align(warning, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        *actwarning = make_show_single_value_activity("Warning", warning_msg, show_help_btn);
    }

    // Buttons - Cancel and Next
    btn_data_t hdrbtns[] = { { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_SIGNTX_REJECT },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNTX_ACCEPT } };

    // Screen items
    btn_data_t menubtns[] = { { .content = splitaddr, .ev_id = BTN_SIGNTX_ADDRESS },
        { .content = splitamount, .ev_id = BTN_SIGNTX_TICKERAMOUNT },
        { .content = assetinfo,
            .txt = is_wallet_output && !assetinfo ? VERIFIED_WALLET_OUTPUT_MSG : NULL,
            .font = GUI_DEFAULT_FONT,
            .ev_id = assetinfo ? BTN_SIGNTX_ASSETINFO : GUI_BUTTON_EVENT_NONE },
        { .content = warning,
            .txt = is_wallet_output && assetinfo && !warning ? VERIFIED_WALLET_OUTPUT_MSG : NULL,
            .font = GUI_DEFAULT_FONT,
            .ev_id = warning ? BTN_SIGNTX_WARNING : GUI_BUTTON_EVENT_NONE } };

    const size_t num_btns = assetinfo || warning || is_wallet_output ? 4 : 2;
    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, num_btns);

    // Set the intially selected item to the 'Next' button
    gui_set_activity_initial_selection(act, hdrbtns[1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(amountvalue, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(addr, true, TFT_BLACK, gui_get_highlight_color());
    if (assetinfo) {
        gui_set_text_scroll_selected(assetinfo, true, TFT_BLACK, gui_get_highlight_color());
    }
    if (warning) {
        gui_set_text_scroll_selected(warning, true, TFT_BLACK, gui_get_highlight_color());
    }

    return act;
}

// Helper to make a screen activity to display an input or output for the user to verify.
// Displays a label or a destination address, passed amount (already formatted for display),
// and the associated ticker if one is passed.
//
// It can also display:
// a) Asset string (eg. issuer + asset-id) for liquid registered assets, and
// b) any warning message that may be associated with this output.
//
// It is not valid to call this with both an address and a label string (but must have one).

static bool show_input_output_activity(const char* title, const bool is_wallet_output, const bool is_address,
    const char* address_label, const char* amount, const char* ticker, const char* issuer, const char* asset_id_hex,
    const char* warning_msg)
{
    JADE_ASSERT(title);
    JADE_ASSERT(address_label);
    JADE_ASSERT(amount);
    JADE_ASSERT(ticker);
    // asset info is both or neither
    JADE_ASSERT(!issuer == !asset_id_hex);
    // warning_msg is optional

    char assethex[96];
    if (asset_id_hex) {
        JADE_ASSERT(strlen(asset_id_hex) == 64);
        const int ret = snprintf(assethex, sizeof(assethex), "%.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s  %.*s", 8,
            asset_id_hex, 8, asset_id_hex + 8, 8, asset_id_hex + 16, 8, asset_id_hex + 24, 8, asset_id_hex + 32, 8,
            asset_id_hex + 40, 8, asset_id_hex + 48, 8, asset_id_hex + 56);
        JADE_ASSERT(ret > 0 && ret < sizeof(assethex));
    } else {
        assethex[0] = '\0';
    }

    gui_activity_t* act_tickeramt = NULL;
    gui_activity_t* act_addr1 = NULL;
    gui_activity_t* act_addr2 = NULL;
    gui_activity_t* act_assetinfo1 = NULL;
    gui_activity_t* act_assetinfo2 = NULL;
    gui_activity_t* act_warning = NULL;
    gui_activity_t* act_summary = make_input_output_activities(title, is_wallet_output, is_address, address_label,
        amount, ticker, issuer, assethex, warning_msg, &act_tickeramt, &act_addr1, &act_addr2, &act_assetinfo1,
        &act_assetinfo2, &act_warning);
    gui_activity_t* act = act_summary;
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
        ev_id = BTN_SIGNTX_ACCEPT;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = (act == act_addr2) ? act_addr1 : act_summary;
                break;

            case BTN_ADDRESS_REJECT:
            case BTN_ADDRESS_ACCEPT:
            case BTN_SIGNTX_ASSETINFO_DONE:
                act = act_summary;
                break;

            case BTN_ADDRESS_NEXT:
                act = act_addr2;
                break;

            case BTN_SIGNTX_ASSETINFO_NEXT:
                act = (act == act_assetinfo1) ? act_assetinfo2 : act_assetinfo1;
                break;

            case BTN_SIGNTX_ADDRESS:
                act = act_addr1;
                break;

            case BTN_SIGNTX_TICKERAMOUNT:
                act = act_tickeramt;
                break;

            case BTN_SIGNTX_ASSETINFO:
                act = act_assetinfo1;
                break;

            case BTN_SIGNTX_WARNING:
                act = act_warning;
                break;

            case BTN_SIGNTX_REJECT:
                return false;

            case BTN_SIGNTX_ACCEPT:
                return true;
            }
        }
    }
}

bool show_btc_transaction_outputs_activity(
    const char* network, const struct wally_tx* tx, const output_info_t* output_info)
{
    JADE_ASSERT(network);
    JADE_ASSERT(tx);
    // Note: output_info is optional and can be null

    // Show outputs which don't have a script
    const bool show_scriptless = true;

    // 1 based indices for display purposes
    uint32_t nDisplayedOutput = 0;
    const uint32_t nTotalOutputsDisplayed = displayable_outputs(tx, output_info, show_scriptless);
    const bool hiddenOutputs = nTotalOutputsDisplayed < tx->num_outputs;

    // NOTE: because signing potentially has a lot of output info to display
    // we deal with the outputs one at a time, rather than creating them all up-front.
    gui_activity_t* act_clear = gui_make_activity();

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        struct wally_tx_output* out = tx->outputs + i;

        // Skip outputs we have automatically validated (eg. change outputs)
        if (hiddenOutputs && !display_output(tx->outputs, output_info, i, show_scriptless)) {
            continue;
        }
        ++nDisplayedOutput;

        // Free all existing activities between outputs
        gui_set_current_activity_ex(act_clear, true);

        const bool is_wallet_output = output_info && (output_info[i].flags & OUTPUT_FLAG_VALIDATED);

        char title[16];
        int ret = snprintf(title, sizeof(title), "Output %ld/%ld", nDisplayedOutput, nTotalOutputsDisplayed);
        JADE_ASSERT(ret > 0 && ret < sizeof(title));

        char amount[32];
        ret = snprintf(amount, sizeof(amount), "%.08f", 1.0 * out->satoshi / 1e8);
        JADE_ASSERT(ret > 0 && ret < sizeof(amount));

        char address[MAX_ADDRESS_LEN];
        script_to_address(network, out->script, out->script_len, out->satoshi > 0, address, sizeof(address));
        const bool is_address = true;

        // Show output info
        const char* msg = (output_info && strlen(output_info[i].message) > 0) ? output_info[i].message : NULL;
        if (!show_input_output_activity(
                title, is_wallet_output, is_address, address, amount, TICKER_BTC, NULL, NULL, msg)) {
            // User pressed 'cancel'
            return false;
        }
        // else user pressed 'next', continue to next output
    }

    // All outputs confirmed
    JADE_ASSERT(nDisplayedOutput == nTotalOutputsDisplayed);
    return true;
}

bool show_elements_transaction_outputs_activity(const char* network, const struct wally_tx* tx,
    const output_info_t* output_info, const asset_info_t* assets, const size_t num_assets)
{
    JADE_ASSERT(network);
    JADE_ASSERT(tx);
    JADE_ASSERT(output_info);
    JADE_ASSERT(assets || !num_assets);

    // Don't show outputs which don't have a script (as these are fees)
    const bool show_scriptless = false;

    // 1 based indices for display purposes
    uint32_t nDisplayedOutput = 0;
    const uint32_t nTotalOutputsDisplayed = displayable_outputs(tx, output_info, show_scriptless);
    const bool hiddenOutputs = nTotalOutputsDisplayed < tx->num_outputs;

    // NOTE: because signing potentially has a lot of output info to display
    // we deal with the outputs one at a time, rather than creating them all up-front.
    gui_activity_t* act_clear = gui_make_activity();

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        struct wally_tx_output* out = tx->outputs + i;

        // Skip outputs we have automatically validated (eg. change outputs)
        // also, skip/hide fees (ie. outputs sans script)
        if (hiddenOutputs && !display_output(tx->outputs, output_info, i, show_scriptless)) {
            continue;
        }
        ++nDisplayedOutput;

        // Free all existing activities between outputs
        gui_set_current_activity_ex(act_clear, true);

        const bool is_wallet_output = output_info[i].flags & OUTPUT_FLAG_VALIDATED;

        char title[16];
        const int ret = snprintf(title, sizeof(title), "Output %ld/%ld", nDisplayedOutput, nTotalOutputsDisplayed);
        JADE_ASSERT(ret > 0 && ret < sizeof(title));

        // Get the address
        char address[MAX_ADDRESS_LEN];
        elements_script_to_address(network, out->script, out->script_len, output_info[i].value > 0,
            (output_info[i].flags & OUTPUT_FLAG_HAS_BLINDING_KEY) ? output_info[i].blinding_key : NULL,
            sizeof(output_info[i].blinding_key), address, sizeof(address));
        const bool is_address = true;

        // If there is no unblinded info, make warning/placeholder screen
        // ATM assert that we always have unblinded info when displaying an output
        JADE_ASSERT(output_info[i].flags & OUTPUT_FLAG_HAS_UNBLINDED);
        if (!(output_info[i].flags & OUTPUT_FLAG_HAS_UNBLINDED)) {
            if (!show_input_output_activity(title, is_wallet_output, is_address, address, "????", "????", "????",
                    "????????????", BLINDED_OUTPUT)) {
                // User pressed 'cancel'
                return false;
            }
            // Move to next output
            continue;
        }

        // Look up the asset-id in the asset-data
        char issuer[128];
        char asset_id_hex[2 * ASSET_TAG_LEN + 1];
        char amount[32];
        char ticker[8]; // Registry tickers are max 5char ... but testnet policy asset ticker is 'L-TEST' ...
        const bool have_asset_info = get_asset_display_info(network, assets, num_assets, output_info[i].asset_id,
            sizeof(output_info[i].asset_id), output_info[i].value, issuer, sizeof(issuer), asset_id_hex,
            sizeof(asset_id_hex), amount, sizeof(amount), ticker, sizeof(ticker));

        // Insert extra screen to display warning if the asset registry information is missing
        if (!have_asset_info) {
            // Make activity with no asset-id but with the warning message
            if (!show_input_output_activity(title, is_wallet_output, is_address, address, amount, ticker, issuer,
                    asset_id_hex, MISSING_ASSET_DATA)) {
                // User pressed 'cancel'
                return false;
            }
        }

        // Normal output screen - with issuer and asset-id
        const char* msg = (output_info && strlen(output_info[i].message) > 0) ? output_info[i].message : NULL;
        if (have_asset_info || msg) {
            if (!show_input_output_activity(
                    title, is_wallet_output, is_address, address, amount, ticker, issuer, asset_id_hex, msg)) {
                // User pressed 'cancel'
                return false;
            }
        }
        // else user pressed 'next', continue to next output
    }

    // All outputs confirmed
    JADE_ASSERT(nDisplayedOutput == nTotalOutputsDisplayed);
    return true;
}

static bool show_elements_asset_summary_activity(const char* title, const char* direction, const char* network,
    const asset_info_t* assets, const size_t num_assets, const movement_summary_info_t* summary,
    const size_t summary_len)
{
    JADE_ASSERT(title);
    JADE_ASSERT(direction);
    JADE_ASSERT(network);
    JADE_ASSERT(assets || !num_assets);
    JADE_ASSERT(summary);
    JADE_ASSERT(summary_len);

    for (size_t i = 0; i < summary_len; ++i) {
        char label[16];
        if (summary_len == 1) {
            // Omit counter if just one input/output
            const int ret = snprintf(label, sizeof(label), "%s", direction);
            JADE_ASSERT(ret > 0 && ret < sizeof(label));
        } else {
            // 1 based indices for display purposes
            const int ret = snprintf(label, sizeof(label), "%s  (%d/%d)", direction, i + 1, summary_len);
            JADE_ASSERT(ret > 0 && ret < sizeof(label));
        }
        const bool is_address = false;
        const bool is_wallet_output = false; // not used in this case

        // Look up the asset-id in the asset-data
        char issuer[128];
        char asset_id_hex[2 * ASSET_TAG_LEN + 1];
        char amount[32];
        char ticker[8]; // Registry tickers are max 5char ... but testnet policy asset ticker is 'L-TEST' ...
        const bool have_asset_info = get_asset_display_info(network, assets, num_assets, summary[i].asset_id,
            sizeof(summary[i].asset_id), summary[i].value, issuer, sizeof(issuer), asset_id_hex, sizeof(asset_id_hex),
            amount, sizeof(amount), ticker, sizeof(ticker));

        // Normal output screen - with issuer and asset-id etc
        const char* msg = !have_asset_info ? MISSING_ASSET_DATA : NULL;
        if (!show_input_output_activity(
                title, is_wallet_output, is_address, label, amount, ticker, issuer, asset_id_hex, msg)) {
            // User pressed 'cancel'
            return false;
        }
        // else user pressed 'next', continue to next summary
    }

    // All summaries confirmed
    return true;
}

bool show_elements_swap_activity(const char* network, const bool initial_proposal,
    const movement_summary_info_t* wallet_input_summary, const size_t wallet_input_summary_size,
    const movement_summary_info_t* wallet_output_summary, const size_t wallet_output_summary_size,
    const asset_info_t* assets, const size_t num_assets)
{
    JADE_ASSERT(network);
    JADE_ASSERT(wallet_input_summary);
    JADE_ASSERT(wallet_input_summary_size);
    JADE_ASSERT(wallet_output_summary);
    JADE_ASSERT(wallet_output_summary_size);
    JADE_ASSERT(assets || !num_assets);

    const char* title = initial_proposal ? "Swap Proposal" : "Complete Swap";

    if (!show_elements_asset_summary_activity(
            title, "Receive", network, assets, num_assets, wallet_output_summary, wallet_output_summary_size)) {
        // User pressed 'cancel'
        return false;
    }

    if (!show_elements_asset_summary_activity(
            title, "Send", network, assets, num_assets, wallet_input_summary, wallet_input_summary_size)) {
        // User pressed 'cancel'
        return false;
    }

    // Both swap legs confirmed
    return true;
}

// Screens to confirm the fee / signing the tx
static gui_activity_t* make_final_confirmation_activities(const char* title, const char* feeamount, const char* ticker,
    const char* warning_msg, gui_activity_t** actfeeamt, gui_activity_t** actwarning)
{
    JADE_ASSERT(title);
    JADE_ASSERT(feeamount);
    JADE_ASSERT(ticker);
    // warning msg is optinal
    JADE_INIT_OUT_PPTR(actfeeamt);
    JADE_INIT_OUT_PPTR(actwarning);

    char display_str[128];
    const bool show_help_btn = false;
    gui_view_node_t* node;

    // First row, fee amount + ticker
    gui_view_node_t* splitfee;
    gui_make_hsplit(&splitfee, GUI_SPLIT_RELATIVE, 3, 18, 52, 30);

    gui_make_text(&node, "Fee:", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, splitfee);

    gui_view_node_t* amountvalue;
    gui_make_text(&amountvalue, feeamount, TFT_WHITE);
    gui_set_align(amountvalue, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(amountvalue, splitfee);

    gui_make_text(&node, ticker, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, splitfee);

    int ret = snprintf(display_str, sizeof(display_str), "%s\n%s", feeamount, ticker);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    *actfeeamt = make_show_single_value_activity("Fee Amount", display_str, show_help_btn);

    // Second row, warning
    gui_view_node_t* warning = NULL;
    if (warning_msg) {
        gui_make_text(&warning, warning_msg, TFT_WHITE);
        gui_set_align(warning, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        *actwarning = make_show_single_value_activity("Warning", warning_msg, show_help_btn);
    }

    // Buttons - Cancel and Confirm
    btn_data_t hdrbtns[] = { { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_SIGNTX_REJECT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_SIGNTX_ACCEPT } };

    btn_data_t menubtns[] = {
        { .content = splitfee, .ev_id = BTN_SIGNTX_TICKERAMOUNT },
        { .content = warning, .font = GUI_DEFAULT_FONT, .ev_id = warning ? BTN_SIGNTX_WARNING : GUI_BUTTON_EVENT_NONE }
    };

    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 2);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(amountvalue, true, TFT_BLACK, gui_get_highlight_color());
    if (warning) {
        gui_set_text_scroll_selected(warning, true, TFT_BLACK, gui_get_highlight_color());
    }

    return act;
}

static bool show_final_confirmation_activity(
    const char* title, const char* feeamount, const char* ticker, const char* warning_msg)
{
    JADE_ASSERT(title);
    JADE_ASSERT(feeamount);
    JADE_ASSERT(ticker);
    // warning_msg is optional

    // final confirmation screen
    gui_activity_t* act_feeamt = NULL;
    gui_activity_t* act_warning = NULL;
    gui_activity_t* const act_summary
        = make_final_confirmation_activities(title, feeamount, ticker, warning_msg, &act_feeamt, &act_warning);
    gui_activity_t* act = act_summary;
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
        ev_id = BTN_SIGNTX_ACCEPT;
#endif

        if (ret) {
            switch (ev_id) {
            case BTN_BACK:
                act = act_summary;
                break;

            case BTN_SIGNTX_TICKERAMOUNT:
                act = act_feeamt;
                break;

            case BTN_SIGNTX_WARNING:
                act = act_warning;
                break;

            case BTN_SIGNTX_REJECT:
                return false;

            case BTN_SIGNTX_ACCEPT:
                return true;
            }
        }
    }
}

bool show_btc_final_confirmation_activity(const uint64_t fee, const char* warning_msg)
{
    char feeamount[32];
    const int ret = snprintf(feeamount, sizeof(feeamount), "%.08f", 1.0 * fee / 1e8);
    JADE_ASSERT(ret > 0 && ret < sizeof(feeamount));

    return show_final_confirmation_activity("Send Transaction", feeamount, TICKER_BTC, warning_msg);
}

bool show_elements_final_confirmation_activity(
    const char* network, const char* title, const uint64_t fee, const char* warning_msg)
{
    JADE_ASSERT(network);
    JADE_ASSERT(title);

    // Policy asset must be present in h/coded asset data, and it must have a 'ticker'
    const char* asset_id_hex = networkGetPolicyAsset(network);
    JADE_ASSERT(asset_id_hex);
    asset_info_t asset_info = {};
    const bool have_asset_info = assets_get_info(network, NULL, 0, asset_id_hex, &asset_info);
    JADE_ASSERT(have_asset_info);
    JADE_ASSERT(asset_info.ticker);
    JADE_ASSERT(asset_info.ticker_len);

    // Ticker
    char ticker[8]; // Registry tickers are max 5char ... but testnet policy asset ticker is 'L-TEST' ...
    int ret = snprintf(ticker, sizeof(ticker), "%.*s", asset_info.ticker_len, asset_info.ticker);
    JADE_ASSERT(ret > 0 && ret < sizeof(ticker));

    // Fee amount scaled and displayed at relevant precision
    char feeamount[32];
    const uint32_t scale_factor = pow(10, asset_info.precision);
    ret = snprintf(feeamount, sizeof(feeamount), "%.*f", asset_info.precision, 1.0 * fee / scale_factor);
    JADE_ASSERT(ret > 0 && ret < sizeof(feeamount));

    return show_final_confirmation_activity(title, feeamount, ticker, warning_msg);
}