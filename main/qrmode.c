#include "qrmode.h"

#include "bcur.h"
#include "button_events.h"
#include "gui.h"
#include "idletimer.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "multisig.h"
#include "otpauth.h"
#include "qrcode.h"
#include "sensitive.h"
#include "storage.h"
#include "ui.h"
#include "utils/address.h"
#include "utils/malloc_ext.h"
#include "wallet.h"

#include <wally_script.h>

#include <string.h>
#include <time.h>

// When we are displaying a BCUR QR code we ensure the timeout is at least this value
// as we don't want the unit to shut down because of apparent inactivity.
#define BCUR_QR_DISPLAY_MIN_TIMEOUT_SECS 300

void make_show_qr_help_activity(gui_activity_t** activity_ptr, const char* url, Icon* qr_icon);

void make_show_xpub_qr_activity(gui_activity_t** activity_ptr, const char* label, const char* pathstr, Icon* icons,
    size_t num_icons, size_t frames_per_qr_icon);
void make_xpub_qr_options_activity(gui_activity_t** activity_ptr, gui_view_node_t** script_textbox,
    gui_view_node_t** multisig_textbox, gui_view_node_t** urtype_textbox);

void make_search_verify_address_activity(
    gui_activity_t** activity_ptr, const char* pathstr, progress_bar_t* progress_bar, gui_view_node_t** index_text);

void make_show_qr_activity(gui_activity_t** activity_ptr, const char* title, const char* label, Icon* icons,
    size_t num_icons, size_t frames_per_qr_icon, bool show_options_button);
void make_qr_options_activity(
    gui_activity_t** activity_ptr, gui_view_node_t** density_textbox, gui_view_node_t** speed_textbox);

bool register_otp_string(const char* otp_uri, const size_t uri_len, const char** errmsg);
int register_multisig_file(const char* multisig_file, const size_t multisig_file_len, const char** errmsg);
int update_pinserver(const CborValue* const params, const char** errmsg);
int params_set_epoch_time(CborValue* params, const char** errmsg);

// PSBT struct and functions
struct wally_psbt;
int sign_psbt(struct wally_psbt* psbt, const char** errmsg);
int wally_psbt_free(struct wally_psbt* psbt);

#define EXPORT_XPUB_PATH_LEN 4

#define ADDRESS_SEARCH_BATCH_SIZE(multisig) (multisig ? 10 : 20)
#define NUM_BATCHES_TO_RECONFIRM(multisig) (multisig ? 20 : 25)
#define NUM_INDEXES_TO_RECONFIRM(multisig) (NUM_BATCHES_TO_RECONFIRM(multisig) * ADDRESS_SEARCH_BATCH_SIZE(multisig))

// Test whether 'flags' contains the entirety of the 'test_flags'
// (ie. maybe compound/multiple bits set)
static inline bool contains_flags(const uint16_t flags, const uint16_t test_flags)
{
    return (flags & test_flags) == test_flags;
}

// Rotate through: low -> high -> high|low -> low -> high ...
// 'unset' treated as 'high' (ie. the middle value)
static void rotate_flags(uint16_t* flags, const uint16_t high, const uint16_t low)
{
    JADE_ASSERT(flags);

    if (contains_flags(*flags, high | low)) {
        *flags &= ~high;
    } else if (contains_flags(*flags, high)) {
        *flags |= low;
    } else if (contains_flags(*flags, low)) {
        *flags ^= (high | low);
    } else { // ie. currently 0/default/uninitialised - treat as 'high'
        *flags |= (high | low);
    }
}

static uint8_t qr_animation_speed_from_flags(const uint16_t qr_flags)
{
    // Frame periods around 800ms, 450ms, 270ms  (see GUI_TARGET_FRAMERATE)
    // Frame rates: HIGH|LOW > HIGH > LOW ...
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_SPEED_HIGH | QR_SPEED_LOW) ? 4 : contains_flags(qr_flags, QR_SPEED_LOW) ? 12 : 7;
}
static const char* qr_animation_speed_desc_from_flags(const uint16_t qr_flags)
{
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_SPEED_HIGH | QR_SPEED_LOW) ? "High"
        : contains_flags(qr_flags, QR_SPEED_LOW)                  ? "Low"
                                                                  : "Medium";
}

static uint8_t qr_version_from_flags(const uint16_t qr_flags)
{
    // QR versions 12, 6 and 4 fit well on the Jade screen with scaling of
    // 2 px-per-cell, 3 px-per-cell, and 4 px-per-cell respectively.
    // Version/Size/Density: HIGH|LOW > HIGH > LOW ... 0 implies unset/default
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_DENSITY_HIGH | QR_DENSITY_LOW) ? 12
        : contains_flags(qr_flags, QR_DENSITY_LOW)                    ? 4
                                                                      : 6;
}
static const char* qr_density_desc_from_flags(const uint16_t qr_flags)
{
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_DENSITY_HIGH | QR_DENSITY_LOW) ? "High"
        : contains_flags(qr_flags, QR_DENSITY_LOW)                    ? "Low"
                                                                      : "Medium";
}

// We support native segwit and p2sh-wrapped segwit, siglesig and multisig
static script_variant_t xpub_script_variant_from_flags(const uint16_t qr_flags)
{
    const bool wrapped_segwit = contains_flags(qr_flags, QR_XPUB_P2SH_WRAPPED);
    if (contains_flags(qr_flags, QR_XPUB_MULTISIG)) {
        return wrapped_segwit ? MULTI_P2WSH_P2SH : MULTI_P2WSH;
    }
    return wrapped_segwit ? P2WPKH_P2SH : P2WPKH;
}

static void create_display_xpub_qr_activity(gui_activity_t** activity_ptr, const uint16_t qr_flags)
{
    JADE_ASSERT(activity_ptr);

    const bool use_format_hdkey = false; // qr_flags & QR_XPUB_HDKEY;  - not currently in use
    const char* const xpub_qr_format = use_format_hdkey ? BCUR_TYPE_CRYPTO_HDKEY : BCUR_TYPE_CRYPTO_ACCOUNT;
    const script_variant_t script_variant = xpub_script_variant_from_flags(qr_flags);

    // Deduce path based on script type and main/test network restrictions
    uint32_t path[EXPORT_XPUB_PATH_LEN]; // 3 or 4 - purpose'/cointype'/account'/[multisig bip48 script type']
    size_t path_len = 0;
    wallet_get_default_xpub_export_path(script_variant, path, EXPORT_XPUB_PATH_LEN, &path_len);

    // Construct BC-UR CBOR message for 'crypto-account' or 'crypto-hdkey' bcur
    uint8_t cbor[128];
    size_t written = 0;
    if (use_format_hdkey) {
        bcur_build_cbor_crypto_hdkey(path, path_len, cbor, sizeof(cbor), &written);
    } else {
        bcur_build_cbor_crypto_account(script_variant, path, path_len, cbor, sizeof(cbor), &written);
    }

    // Map BCUR cbor into a series of QR-code icons
    Icon* icons = NULL;
    size_t num_icons = 0;
    const uint8_t qrcode_version = qr_version_from_flags(qr_flags);
    bcur_create_qr_icons(cbor, written, xpub_qr_format, qrcode_version, &icons, &num_icons);

    // Create xpub activity for those icons
    char pathstr[32];
    const bool ret = bip32_path_as_str(path, path_len, pathstr, sizeof(pathstr));
    JADE_ASSERT(ret);
    const char* label = qr_flags & QR_XPUB_MULTISIG ? "Multisig" : "Singlesig";
    const uint8_t frames_per_qr = qr_animation_speed_from_flags(qr_flags);
    make_show_xpub_qr_activity(activity_ptr, label, pathstr, icons, num_icons, frames_per_qr);
    JADE_ASSERT(*activity_ptr);
}

static bool handle_xpub_options(uint16_t* qr_flags)
{
    JADE_ASSERT(qr_flags);

    gui_activity_t* activity = NULL;
    gui_view_node_t* script_textbox = NULL;
    gui_view_node_t* multisig_textbox = NULL;
    gui_view_node_t* urtype_textbox = NULL;
    make_xpub_qr_options_activity(&activity, &script_textbox, &multisig_textbox, &urtype_textbox);
    JADE_ASSERT(activity);
    JADE_ASSERT(script_textbox);
    JADE_ASSERT(multisig_textbox);
    JADE_ASSERT(!urtype_textbox); // not currently in use

    const uint16_t initial_flags = *qr_flags;
    while (true) {
        // Update options
        gui_update_text(script_textbox, *qr_flags & QR_XPUB_P2SH_WRAPPED ? "Wrapped Segwit" : "Native Segwit");
        gui_update_text(multisig_textbox, *qr_flags & QR_XPUB_MULTISIG ? "Multisig" : "Singlesig");
        // gui_update_text(urtype_textbox, *qr_flags & QR_XPUB_HDKEY ? "HDKey" : "Account");  // not currently in use

        // Show, and await button click
        gui_set_current_activity(activity);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_XPUB_TOGGLE_SCRIPT) {
                *qr_flags ^= QR_XPUB_P2SH_WRAPPED;
            } else if (ev_id == BTN_XPUB_TOGGLE_MULTISIG) {
                *qr_flags ^= QR_XPUB_MULTISIG;
                //} else if (ev_id == BTN_XPUB_TOGGLE_BCUR_TYPE) {
                //    *qr_flags ^= QR_XPUB_HDKEY;
            } else if (ev_id == BTN_XPUB_OPTIONS_HELP) {
                await_qr_help_activity("blockstream.com/xpub");
            } else if (ev_id == BTN_XPUB_OPTIONS_EXIT) {
                // Done
                break;
            }
        }
    }

    // If nothing was updated, return false
    if (initial_flags == *qr_flags) {
        return false;
    }

    // Persist prefereces and return true to indicate they were changed
    storage_set_qr_flags(*qr_flags);
    return true;
}

// Display singlesig xpub qr code
void display_xpub_qr(void)
{
    uint16_t qr_flags = storage_get_qr_flags();

    // Create show xpub activity for those icons
    gui_activity_t* activity = NULL;
    create_display_xpub_qr_activity(&activity, qr_flags);
    JADE_ASSERT(activity);

    while (true) {
        // Show, and await button click
        gui_set_current_activity(activity);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_XPUB_OPTIONS) {
                if (handle_xpub_options(&qr_flags)) {
                    // Options were updated - re-create xpub screen
                    create_display_xpub_qr_activity(&activity, qr_flags);
                }
            } else if (ev_id == BTN_XPUB_EXIT) {
                // Done
                break;
            }
        }
    }
}

// Helper to get user to select multisig record to use
static bool select_multisig_record(char names[][MAX_MULTISIG_NAME_SIZE], const size_t num_names, size_t* selected)
{
    JADE_ASSERT(names);
    JADE_ASSERT(num_names);
    JADE_INIT_OUT_SIZE(selected);

    // Otherwise offer choice of multisig names
    gui_activity_t* activity = NULL;
    gui_view_node_t* item_text = NULL;
    make_show_label_activity(&activity, "Multisig Address", "Select multisig wallet:", &item_text);
    JADE_ASSERT(activity);
    JADE_ASSERT(item_text);
    gui_set_current_activity(activity);

    const size_t limit = num_names + 1;
    while (true) {
        JADE_ASSERT(*selected < limit);
        if (*selected < num_names) {
            gui_update_text(item_text, names[*selected]);
        } else {
            gui_update_text(item_text, "< Cancel >");
        }

        // wait for a GUI event
        int32_t ev_id = 0;
        gui_activity_wait_event(activity, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case GUI_WHEEL_LEFT_EVENT:
            *selected = (*selected + limit - 1) % limit;
            break;

        case GUI_WHEEL_RIGHT_EVENT:
            *selected = (*selected + 1) % limit;
            break;

        default:
            if (ev_id == gui_get_click_event()) {
                return *selected < num_names;
            }
        }
    }
}

// Verify an address string by brute-forcing
static bool verify_address(const address_data_t* const addr_data)
{
    JADE_ASSERT(addr_data);

    JADE_ASSERT(addr_data->network);
    JADE_ASSERT(addr_data->script_len);

    char buf[160];
    int rc = snprintf(buf, sizeof(buf), "Attempt to verify address?\n\n%s", addr_data->address);
    JADE_ASSERT(rc > 0 && rc < sizeof(buf));
    if (!await_yesno_activity("Verify Address", buf, true)) {
        return false;
    }

    // check network - eg. testnet address, but this jade is setup for mainnet only
    if (!keychain_is_network_type_consistent(addr_data->network)) {
        await_error_activity("Network type inconsistent");
        return false;
    }

    // Get the script type
    size_t script_type = 0;
    if (wally_scriptpubkey_get_type(addr_data->script, addr_data->script_len, &script_type) != WALLY_OK) {
        await_error_activity("Failed to parse scriptpubkey");
        return false;
    }

    char label[32];
    script_variant_t variant;
    bool is_multisig = false;
    uint8_t threshold = 0;
    bool sorted = false;
    struct ext_key* search_roots = NULL;
    size_t search_roots_len = 0;

    // If it is (or might be) multisig, ask the user to select one, and load details
    if (script_type == WALLY_SCRIPT_TYPE_P2SH || script_type == WALLY_SCRIPT_TYPE_P2WSH) {
        // Could be multisig - offer choice of multisig records
        char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
        const size_t num_names = sizeof(names) / sizeof(names[0]);
        size_t num_multisigs = 0;
        multisig_get_valid_record_names(&script_type, names, num_names, &num_multisigs);

        // p2sh-wrapped could be multi- or single- sig.  User to select which.
        if (script_type != WALLY_SCRIPT_TYPE_P2SH
            || await_yesno_activity("Multisig Address", "\nIs this a multisig address?", false)) {
            // Must have a multisig record - user to select
            size_t selected = 0;
            if (!num_multisigs || !select_multisig_record(names, num_multisigs, &selected)) {
                JADE_LOGE("No relevant multisig records found/selected for multisig address");
                await_error_activity("Register multisig record\nbefore attempting to\nverify multisig addresses");
                return false;
            }
            JADE_ASSERT(selected < num_multisigs);

            const char* errmsg = NULL;
            multisig_data_t multisig_data;
            if (!multisig_load_from_storage(names[selected], &multisig_data, &errmsg)) {
                await_error_activity("Failed to load multisig record");
                return false;
            }

            // 'multisig_data' is populated - copy key fields
            is_multisig = true;
            variant = multisig_data.variant;
            sorted = multisig_data.sorted;
            threshold = multisig_data.threshold;
            search_roots_len = multisig_data.num_xpubs;
            search_roots = JADE_CALLOC(search_roots_len, sizeof(struct ext_key));

            // Derive set of multisig parent keys
            const uint32_t path[] = { 0 }; // 'external' (ie. not internal change) address
            for (int i = 0; i < search_roots_len; ++i) {
                const uint8_t* xpub = multisig_data.xpubs + (i * BIP32_SERIALIZED_LEN);
                const bool ret = wallet_derive_pubkey(xpub, BIP32_SERIALIZED_LEN, path, 1,
                    BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &search_roots[i]);
                JADE_ASSERT(ret);
            }

            // Use multisig name as ui label.
            rc = snprintf(label, sizeof(label), "<%s>/0", names[selected]);
            JADE_ASSERT(rc > 0 && rc < sizeof(label));
        }
    }

    // If not multisig, must be singlesig
    if (!is_multisig) {
        JADE_ASSERT(!search_roots);
        JADE_ASSERT(!search_roots_len);
        JADE_ASSERT(!threshold);

        if (!get_singlesig_variant_from_script_type(script_type, &variant)) {
            await_error_activity("Address scriptpubkey unsupported");
            return false;
        }

        // Get the path to search
        uint32_t path[EXPORT_XPUB_PATH_LEN];
        size_t path_len = 0;
        wallet_get_default_xpub_export_path(variant, path, EXPORT_XPUB_PATH_LEN, &path_len);
        JADE_ASSERT(path_len == EXPORT_XPUB_PATH_LEN - 1);
        path[path_len++] = 0; // 'external' (ie. not internal change) address

        // Get as hdkey
        search_roots_len = 1;
        search_roots = JADE_CALLOC(search_roots_len, sizeof(struct ext_key));
        bool ret = wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, search_roots);
        JADE_ASSERT(ret);

        // Use the root bip32 path as the label
        ret = bip32_path_as_str(path, path_len, label, sizeof(label));
        JADE_ASSERT(ret);
    }

    gui_activity_t* activity = NULL;
    gui_view_node_t* index_text = NULL;
    progress_bar_t progress_bar = {};
    make_search_verify_address_activity(&activity, label, &progress_bar, &index_text);
    JADE_ASSERT(activity);
    JADE_ASSERT(index_text);

    // Make an event-data structure to track events - attached to the activity
    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(activity);
    JADE_ASSERT(event_data);

    // ... and register against the activity - we will await btn events later
    gui_activity_register_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    size_t index = 0;
    size_t confirmed_at_index = index;
    bool verified = false;
    const size_t address_search_batch_size = ADDRESS_SEARCH_BATCH_SIZE(is_multisig);
    const size_t num_indexes_to_reconfirm = NUM_INDEXES_TO_RECONFIRM(is_multisig);
    while (!verified) {
        gui_set_current_activity(activity);

        // Update the progress bar and text label
        char idx_txt[12];
        rc = snprintf(idx_txt, sizeof(idx_txt), "%u", index);
        JADE_ASSERT(rc > 0 && rc < sizeof(idx_txt));
        update_progress_bar(&progress_bar, num_indexes_to_reconfirm, index - confirmed_at_index);
        gui_update_text(index_text, idx_txt);

        // Search a small batch of paths for the address script
        // NOTE: 'index' is updated as we go along
        JADE_ASSERT(search_roots);
        if (is_multisig) {
            verified = wallet_search_for_multisig_script(variant, sorted, threshold, search_roots, search_roots_len,
                &index, address_search_batch_size, addr_data->script, addr_data->script_len);
        } else {
            JADE_ASSERT(search_roots_len == 1);
            verified = wallet_search_for_singlesig_script(
                variant, &search_roots[0], &index, address_search_batch_size, addr_data->script, addr_data->script_len);
        }

        if (verified) {
            // Address script found and matched - verified
            // NOTE: 'index' will hold the relevant value
            JADE_LOGI("Found script at index: %u", index);
            break;
        }

        // Every so often suggest to user that they might want to abandon the search
        if (index >= confirmed_at_index + num_indexes_to_reconfirm) {
            rc = snprintf(
                buf, sizeof(buf), "Failed to verify address.\n\nCheck next %u addresses?", num_indexes_to_reconfirm);
            JADE_ASSERT(rc > 0 && rc < sizeof(buf));
            if (!await_yesno_activity("Verify Address", buf, true)) {
                // Abandon - exit loop
                break;
            }
            confirmed_at_index = index;
        } else {
            // Giver user a chance to exit or to skip this batch of addresses
            int32_t ev_id = 0;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
            const bool ret = sync_wait_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL,
                                 10 / portTICK_PERIOD_MS)
                == ESP_OK;
#else
            sync_wait_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, NULL, NULL,
                CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
            const bool ret = index > 4 * num_indexes_to_reconfirm; // let it run for a few batches, then exit
            ev_id = BTN_SCAN_ADDRESS_EXIT;
#endif
            if (ret) {
                if (ev_id == BTN_SCAN_ADDRESS_SKIP_ADDRESSES) {
                    // Jump to end of this batch
                    index = confirmed_at_index + num_indexes_to_reconfirm;
                    confirmed_at_index = index;
                } else if (ev_id == BTN_SCAN_ADDRESS_EXIT) {
                    // Abandon - exit loop
                    break;
                }
            }
        }
    }

    if (verified) {
        rc = snprintf(buf, sizeof(buf), "Address verified for:\n\n%s/%u", label, index);
        JADE_ASSERT(rc > 0 && rc < sizeof(buf));
        await_message_activity(buf);
    } else {
        await_error_activity("Address NOT verified!");
    }

    free(search_roots);
    return verified;
}

// Handle QR Options dialog - ie. QR size and frame-rate
static bool handle_qr_options(uint16_t* qr_flags)
{
    JADE_ASSERT(qr_flags);

    gui_activity_t* activity = NULL;
    gui_view_node_t* density_textbox = NULL;
    gui_view_node_t* speed_textbox = NULL;
    make_qr_options_activity(&activity, &density_textbox, &speed_textbox);
    JADE_ASSERT(activity);
    JADE_ASSERT(density_textbox);
    JADE_ASSERT(speed_textbox);

    const uint16_t initial_flags = *qr_flags;
    while (true) {
        // Update options
        gui_update_text(density_textbox, qr_density_desc_from_flags(*qr_flags));
        gui_update_text(speed_textbox, qr_animation_speed_desc_from_flags(*qr_flags));

        // Show, and await button click
        gui_set_current_activity(activity);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_EXIT;
#endif
        if (ret) {
            // NOTE: For Density and Speed :- HIGH|LOW > HIGH > LOW
            // Rotate through: LOW -> HIGH -> HIGH|LOW -> LOW -> ...
            // unset/default is treated as HIGH ie. the middle value
            if (ev_id == BTN_QR_TOGGLE_DENSITY) {
                rotate_flags(qr_flags, QR_DENSITY_HIGH, QR_DENSITY_LOW);
            } else if (ev_id == BTN_QR_TOGGLE_SPEED) {
                rotate_flags(qr_flags, QR_SPEED_HIGH, QR_SPEED_LOW);
            } else if (ev_id == BTN_QR_OPTIONS_HELP) {
                await_qr_help_activity("blockstream.com/scan");
            } else if (ev_id == BTN_QR_OPTIONS_EXIT) {
                // Done
                break;
            }
        }
    }

    // If nothing was updated, return false
    if (initial_flags == *qr_flags) {
        return false;
    }

    // Persist prefereces and return true to indicate they were changed
    storage_set_qr_flags(*qr_flags);
    return true;
}

// Create activity to display (potentially multi-frame/animated) qr
static void create_display_bcur_qr_activity(gui_activity_t** activity_ptr, const char* title, const char* label,
    const char* bcur_type, const uint8_t* cbor, const size_t cbor_len, const uint16_t qr_flags)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(title);
    JADE_ASSERT(label);
    JADE_ASSERT(bcur_type);
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    // Map BCUR cbor into a series of QR-code icons
    Icon* icons = NULL;
    size_t num_icons = 0;
    const uint8_t qrcode_version = qr_version_from_flags(qr_flags);
    bcur_create_qr_icons(cbor, cbor_len, bcur_type, qrcode_version, &icons, &num_icons);

    // Create qr activity for those icons
    const bool show_options_button = true;
    const uint8_t frames_per_qr = qr_animation_speed_from_flags(qr_flags);
    make_show_qr_activity(activity_ptr, title, label, icons, num_icons, frames_per_qr, show_options_button);
    JADE_ASSERT(*activity_ptr);
}

// Display a QR code, with access to size_speed options
static void display_bcur_qr(
    const char* title, const char* label, const char* bcur_type, const uint8_t* cbor, const size_t cbor_len)
{
    JADE_ASSERT(title);
    JADE_ASSERT(label);
    JADE_ASSERT(bcur_type);
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    uint16_t qr_flags = storage_get_qr_flags();

    // When displaying a bcur qr code we set the minimum idle timeout to keep the hw from sleeping too quickly
    // (If the user has set a longer timeout value that is respected)
    idletimer_set_min_timeout_secs(BCUR_QR_DISPLAY_MIN_TIMEOUT_SECS);

    // Create show psbt activity for those icons
    gui_activity_t* activity = NULL;
    create_display_bcur_qr_activity(&activity, title, label, bcur_type, cbor, cbor_len, qr_flags);
    JADE_ASSERT(activity);

    while (true) {
        // Show, and await button click
        gui_set_current_activity(activity);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_QR_DISPLAY_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_QR_OPTIONS) {
                if (handle_qr_options(&qr_flags)) {
                    // Options were updated - re-create psbt qr screen
                    display_message_activity("Processing...");
                    create_display_bcur_qr_activity(&activity, title, label, bcur_type, cbor, cbor_len, qr_flags);
                }
            } else if (ev_id == BTN_QR_DISPLAY_EXIT) {
                // Done
                break;
            }
        }
    }

    // Remove the minimum idle timeout
    idletimer_set_min_timeout_secs(0);
}

// Handle undifferentiated byte string friom QR code
// ie. raw data (not BC-UR wrapped), OR the payload of a UR:BYTES message
static bool handle_qr_bytes(const uint8_t* bytes, const size_t bytes_len)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len);

    const char* strbytes = (const char*)bytes;

    // Try to handle as otp string
    if (bytes_len > sizeof(OTP_SCHEMA_FULL) && !strncasecmp(strbytes, OTP_SCHEMA_FULL, sizeof(OTP_SCHEMA_FULL) - 1)) {
        // Looks like an OTP URI
        const char* errmsg = NULL;
        const int errcode = register_otp_string(strbytes, bytes_len, &errmsg);
        if (errcode) {
            JADE_LOGE("Processing OTP URI failed: %s", errmsg);
            return false;
        }
        return true;
    }

    // Try to handle as multisig file
    if (strcasestr(strbytes, "Name") && strcasestr(strbytes, "Format") && strcasestr(strbytes, "Policy")
        && strcasestr(strbytes, "Derivation")) {
        // Looks like a multisig registration file
        const char* errmsg = NULL;
        const int errcode = register_multisig_file(strbytes, bytes_len, &errmsg);
        if (errcode) {
            JADE_LOGE("Processing multisig file failed: %s", errmsg);
            if (errcode != CBOR_RPC_USER_CANCELLED) {
                await_error_activity(errmsg);
            }
            return false;
        }
        return true;
    }

    JADE_LOGW("Unhandled BC-UR BYTES message");
    await_error_activity("Unhandled QR payload");
    return false;
}

// Unwrap UR:BYTES message and pass payload bytes to above handler
static bool handle_bcur_bytes(const uint8_t* cbor, const size_t cbor_len)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    const uint8_t* bytes = NULL;
    size_t bytes_len = 0;
    if (!bcur_parse_bytes(cbor, cbor_len, &bytes, &bytes_len)) {
        await_error_activity("Invalid QR/BYTES format");
        return false;
    }
    return handle_qr_bytes(bytes, bytes_len);
}

// Parse a BC-UR PSBT and attempt to sign and display as BC-UR QR
static bool parse_sign_display_bcur_psbt_qr(const uint8_t* cbor, const size_t cbor_len)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    // Parse scanned QR data
    struct wally_psbt* psbt = NULL;
    if (!bcur_parse_psbt(cbor, cbor_len, &psbt)) {
        // Unexpected type/format
        await_error_activity("Unsupported QR/PSBT format");
        return false;
    }

    // Try to sign extracted PSBT
    bool ret = false;
    const char* errmsg = NULL;
    const int errcode = sign_psbt(psbt, &errmsg);
    if (errcode) {
        if (errcode != CBOR_RPC_USER_CANCELLED) {
            await_error_activity(errmsg);
        }
        goto cleanup;
    }

    // Build BCUR message holding the signed PSBT
    uint8_t* cbor_signed = NULL;
    size_t cbor_signed_len = 0;
    if (!bcur_build_cbor_crypto_psbt(psbt, &cbor_signed, &cbor_signed_len)) {
        JADE_LOGW("Failed to build bcur/cbor for psbt");
        return false;
    }

    // Now display bcur QR
    display_bcur_qr("PSBT Export", "Scan using\nwallet app", BCUR_TYPE_CRYPTO_PSBT, cbor_signed, cbor_signed_len);

cleanup:
    JADE_WALLY_VERIFY(wally_psbt_free(psbt));
    return ret;
}

// Accept an epoch (time) message via qr code
static bool handle_epoch_qr(const uint8_t* cbor, const size_t cbor_len)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    // Parse cbor
    CborValue root;
    CborValue params;
    CborParser parser;
    if (!bcur_parse_jade_message(cbor, cbor_len, &parser, &root, "set_epoch", &params)) {
        JADE_LOGE("Failed to parse Jade epoch message");
        await_error_activity("Error parsing epoch data");
        return false;
    }

    const char* errmsg = NULL;
    const int errcode = params_set_epoch_time(&params, &errmsg);
    if (errcode) {
        if (errcode != CBOR_RPC_USER_CANCELLED) {
            JADE_LOGE("Error setting epoch time: %s", errmsg);
            char buf[128];
            const int ret = snprintf(buf, sizeof(buf), "Error setting epoch time\n%s", errmsg);
            JADE_ASSERT(ret > 0 && ret < sizeof(buf));
            await_error_activity(buf);
        }
        return false;
    }

    char msg[128];
    char timestr[32];
    const uint64_t epoch_value = time(NULL);
    ctime_r((const time_t*)&epoch_value, timestr);
    const int ret = snprintf(msg, sizeof(msg), "Time set successfully\n\n %s", timestr);
    JADE_ASSERT(ret > 0 && ret < sizeof(msg));
    await_message_activity(msg);

    return true;
}

// Accept an update-pinserver message via qr code
bool handle_update_pinserver_qr(const uint8_t* cbor, const size_t cbor_len)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    // Parse cbor
    CborValue root;
    CborValue params;
    CborParser parser;
    if (!bcur_parse_jade_message(cbor, cbor_len, &parser, &root, "update_pinserver", &params)) {
        JADE_LOGE("Failed to parse Jade pinserver message");
        await_error_activity("Error parsing PinServer data");
        return false;
    }

    const char* errmsg = NULL;
    const int errcode = update_pinserver(&params, &errmsg);
    if (errcode) {
        if (errcode != CBOR_RPC_USER_CANCELLED) {
            JADE_LOGE("Error updating pinserver details: %s", errmsg);
            char buf[128];
            const int ret = snprintf(buf, sizeof(buf), "Error updating PinServer\n%s", errmsg);
            JADE_ASSERT(ret > 0 && ret < sizeof(buf));
            await_error_activity(buf);
        }
        return false;
    }
    return true;
}

// Handle scanning a QR - supports addresses and PSBTs
void handle_scan_qr(void)
{
    // Scan QR - potentially a BC-UR/multi-frame QR
    char* type = NULL;
    uint8_t* data = NULL;
    size_t data_len = 0;
    if (!bcur_scan_qr("Scan supported\nQR code", &type, &data, &data_len) || !data) {
        // Scan aborted
        JADE_ASSERT(!type);
        JADE_ASSERT(!data);
        return;
    }

    if (type) {
        // BC-UR scanned - check type string
        if (!strcasecmp(type, BCUR_TYPE_CRYPTO_PSBT)) {
            // PSBT
            if (!parse_sign_display_bcur_psbt_qr(data, data_len)) {
                JADE_LOGE("Processing BC-UR as PSBT failed");
            }
        } else if (!strcasecmp(type, BCUR_TYPE_JADE_EPOCH)) {
            // Epoch value
            if (!handle_epoch_qr(data, data_len)) {
                JADE_LOGE("Processing BC-UR as epoch failed");
            }
        } else if (!strcasecmp(type, BCUR_TYPE_JADE_UPDPS)) {
            // Pinserver details
            if (!handle_update_pinserver_qr(data, data_len)) {
                JADE_LOGE("Processing BC-UR as pinserver details failed");
            }
        } else if (!strcasecmp(type, BCUR_TYPE_BYTES)) {
            // Opaque bytes
            if (!handle_bcur_bytes(data, data_len)) {
                JADE_LOGE("Processing BC-UR BYTES failed");
            }
        } else {
            // Other - unhandled
            JADE_LOGW("Unhandled BC-UR type: %s", type);
            await_error_activity("Unhandled UR message");
        }
    } else {
        // Non-BC-UR (single frame) undifferentiated bytes
        JADE_ASSERT(data[data_len] == '\0');

        // Try address first, otherwise pass to undifferentiated bytes handler
        address_data_t addr_data;
        if (parse_address((const char*)data, &addr_data)) {
            if (!verify_address(&addr_data)) {
                JADE_LOGW("Verifying address failed: %s", (const char*)data);
            }
        } else if (!handle_qr_bytes(data, data_len)) {
            JADE_LOGW("Unhandled QR message");
            await_error_activity("Failed to process QR code");
        }
    }

    // In either case we need to free the scanned data
    free(type);
    free(data);
}

// Populate an Icon with a QR code of text
// Handles up to v6 codes - ie. text up to 134 bytes
// Caller takes ownership of Icon data and must free
static void bytes_to_qr_icon(const uint8_t* bytes, const size_t bytes_len, const bool large_icons, Icon* const qr_icon)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len);
    JADE_ASSERT(bytes_len < 134); // v6, binary
    JADE_ASSERT(qr_icon);

    // Create icon for url
    // For sizes, see: https://www.qrcode.com/en/about/version.html - 'Binary'
    const uint8_t qr_version = bytes_len < 32 ? 2 : bytes_len < 78 ? 4 : 6;
    const uint8_t scale_factor = (qr_version == 2 ? 4 : qr_version == 4 ? 3 : 2) + (large_icons ? 1 : 0);

    // Convert url to qr code, then to Icon
    QRCode qrcode;
    uint8_t qrbuffer[256]; // opaque work area
    JADE_ASSERT(qrcode_getBufferSize(qr_version) <= sizeof(qrbuffer));
    const int qret = qrcode_initBytes(&qrcode, qrbuffer, qr_version, ECC_LOW, (uint8_t*)bytes, bytes_len);
    JADE_ASSERT(qret == 0);

    qrcode_toIcon(&qrcode, qr_icon, scale_factor);
}

// Display screen with help url and qr code
// Handles up to v6. codes - ie text up to 134 bytes
void await_single_qr_activity(const char* title, const char* label, const uint8_t* data, const size_t data_len)
{
    JADE_ASSERT(title);
    JADE_ASSERT(label);
    JADE_ASSERT(data);
    JADE_ASSERT(data_len);

    const bool large_icons = true;
    Icon* const qr_icon = JADE_MALLOC(sizeof(Icon));
    bytes_to_qr_icon(data, data_len, large_icons, qr_icon);

    // Show, and await button click - note gui takes ownership of icon
    gui_activity_t* activity = NULL;
    make_show_qr_activity(&activity, title, label, qr_icon, 1, 0, false);
    JADE_ASSERT(activity);
    gui_set_current_activity(activity);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_QR_DISPLAY_EXIT, NULL, NULL, NULL, 0);
#else
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_QR_DISPLAY_EXIT, NULL, NULL, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
#endif
}

// Display screen with help url and qr code
// Handles up to v4 codes - ie text up to 78 bytes
void await_qr_help_activity(const char* url)
{
    JADE_ASSERT(url);

    const size_t url_len = strlen(url);
    JADE_ASSERT(url_len < 78); // v4, binary

    const bool large_icons = false;
    Icon* const qr_icon = JADE_MALLOC(sizeof(Icon));
    bytes_to_qr_icon((const uint8_t*)url, url_len, large_icons, qr_icon);

    // Show, and await button click - note gui takes ownership of icon
    gui_activity_t* activity = NULL;
    make_show_qr_help_activity(&activity, url, qr_icon);
    JADE_ASSERT(activity);
    gui_set_current_activity(activity);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_EXIT_QR_HELP, NULL, NULL, NULL, 0);
#else
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, BTN_EXIT_QR_HELP, NULL, NULL, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
#endif
}
