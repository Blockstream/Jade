#include "qrmode.h"

#include "bcur.h"
#include "button_events.h"
#include "gui.h"
#include "idletimer.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "multisig.h"
#include "otpauth.h"
#include "process.h"
#include "qrcode.h"
#include "sensitive.h"
#include "storage.h"
#include "ui.h"
#include "utils/address.h"
#include "utils/malloc_ext.h"
#include "utils/network.h"
#include "wallet.h"

#include <wally_script.h>

#include <string.h>
#include <time.h>

#define MNEMONIC_BUFLEN 256

#define ACCOUNT_INDEX_MAX 65536
#define ACCOUNT_INDEX_FLAGS_SHIFT 16

// When we are displaying a BCUR QR code we ensure the timeout is at least this value
// as we don't want the unit to shut down because of apparent inactivity.
#define BCUR_QR_DISPLAY_MIN_TIMEOUT_SECS 300

gui_activity_t* make_show_qr_help_activity(const char* url, Icon* qr_icon);
gui_activity_t* make_qr_back_continue_activity(
    const char* label, const char* url, const Icon* qr_icon, bool default_selection);

gui_activity_t* make_show_xpub_qr_activity(
    const char* label, const char* pathstr, Icon* icons, size_t num_icons, size_t frames_per_qr_icon);
gui_activity_t* make_xpub_qr_options_activity(
    gui_view_node_t** script_textbox, gui_view_node_t** wallet_textbox, gui_view_node_t** density_textbox);

gui_activity_t* make_search_verify_address_activity(
    const char* root_label, gui_view_node_t** label_text, progress_bar_t* progress_bar, gui_view_node_t** index_text);
gui_activity_t* make_search_address_options_activity(
    bool show_account, gui_view_node_t** account_textbox, gui_view_node_t** change_textbox);

gui_activity_t* make_show_qr_activity(const char* label, Icon* icons, size_t num_icons, size_t frames_per_qr_icon,
    bool show_options_button, bool show_help_btn);
gui_activity_t* make_qr_options_activity(gui_view_node_t** density_textbox, gui_view_node_t** framerate_textbox);

bool import_mnemonic(const uint8_t* bytes, size_t bytes_len, char* buf, size_t buf_len, size_t* written);
bool register_otp_string(const char* otp_uri, size_t uri_len, const char** errmsg);
int register_multisig_file(const char* multisig_file, size_t multisig_file_len, const char** errmsg);
int update_pinserver(const CborValue* const params, const char** errmsg);
int params_set_epoch_time(CborValue* params, const char** errmsg);
int sign_message_file(
    const char* str, size_t str_len, uint8_t* sig_output, size_t sig_len, size_t* written, const char** errmsg);
int get_bip85_bip39_entropy_cbor(const CborValue* params, CborEncoder* output, const char** errmsg);

bool show_confirm_address_activity(const char* address, bool default_selection);

bool handle_mnemonic_qr(const char* mnemonic);

// PSBT struct and functions
struct wally_psbt;
int sign_psbt(const char* network, struct wally_psbt* psbt, const char** errmsg);
int wally_psbt_free(struct wally_psbt* psbt);

#define EXPORT_XPUB_PATH_LEN 4

#define ADDRESS_SEARCH_BATCH_SIZE(multisig) (multisig ? 10 : 20)
#define NUM_BATCHES_TO_RECONFIRM(multisig) (multisig ? 20 : 25)
#define NUM_INDEXES_TO_RECONFIRM(multisig) (NUM_BATCHES_TO_RECONFIRM(multisig) * ADDRESS_SEARCH_BATCH_SIZE(multisig))

// Test whether 'flags' contains the entirety of the 'test_flags'
// (ie. maybe compound/multiple bits set)
static inline bool contains_flags(const uint32_t flags, const uint32_t test_flags)
{
    return (flags & test_flags) == test_flags;
}

// Rotate through: low -> high -> high|low -> low -> high ...
// 'unset' treated as 'high' (ie. the middle value)
static void rotate_flags(uint32_t* flags, const uint32_t high, const uint32_t low)
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

static uint8_t qr_framerate_from_flags(const uint32_t qr_flags)
{
    // Frame periods around 800ms, 450ms, 270ms  (see GUI_TARGET_FRAMERATE)
    // Frame rates: HIGH|LOW > HIGH > LOW ...
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_SPEED_HIGH | QR_SPEED_LOW) ? 4 : contains_flags(qr_flags, QR_SPEED_LOW) ? 12 : 7;
}
static const char* qr_framerate_desc_from_flags(const uint32_t qr_flags)
{
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_SPEED_HIGH | QR_SPEED_LOW) ? "High"
        : contains_flags(qr_flags, QR_SPEED_LOW)                  ? "Low"
                                                                  : "Medium";
}

static uint8_t qr_version_from_flags(const uint32_t qr_flags)
{
    // QR versions 12, 6 and 4 fit well on the Jade screen with scaling of
    // 2 px-per-cell, 3 px-per-cell, and 4 px-per-cell respectively.
    // Version/Size/Density: HIGH|LOW > HIGH > LOW ... 0 implies unset/default
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_DENSITY_HIGH | QR_DENSITY_LOW) ? 12
        : contains_flags(qr_flags, QR_DENSITY_LOW)                    ? 4
                                                                      : 6;
}
static const char* qr_density_desc_from_flags(const uint32_t qr_flags)
{
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_DENSITY_HIGH | QR_DENSITY_LOW) ? "High"
        : contains_flags(qr_flags, QR_DENSITY_LOW)                    ? "Low"
                                                                      : "Medium";
}

// We support native segwit and p2sh-wrapped segwit, singlesig and multisig
static script_variant_t xpub_script_variant_from_flags(const uint32_t qr_flags)
{
    // unset/default is treated as 'high' (ie. the middle value)
    if (contains_flags(qr_flags, QR_XPUB_MULTISIG)) {
        return contains_flags(qr_flags, QR_XPUB_WITNESS | QR_XPUB_LEGACY) ? MULTI_P2WSH_P2SH
            : contains_flags(qr_flags, QR_XPUB_LEGACY)                    ? MULTI_P2SH
                                                                          : MULTI_P2WSH;
    }
    return contains_flags(qr_flags, QR_XPUB_WITNESS | QR_XPUB_LEGACY) ? P2WPKH_P2SH
        : contains_flags(qr_flags, QR_XPUB_LEGACY)                    ? P2PKH
                                                                      : P2WPKH;
}
static inline const char* xpub_scripttype_desc_from_flags(const uint32_t qr_flags)
{
    // unset/default is treated as 'high' (ie. the middle value)
    return contains_flags(qr_flags, QR_XPUB_WITNESS | QR_XPUB_LEGACY) ? "Wrapped Segwit"
        : contains_flags(qr_flags, QR_XPUB_LEGACY)                    ? "Legacy"
                                                                      : "Native Segwit";
}
static inline const char* xpub_wallettype_desc_from_flags(const uint32_t qr_flags)
{
    // unset/default is treated as singlesig
    return contains_flags(qr_flags, QR_XPUB_MULTISIG) ? "Multisig" : "Singlesig";
}

static gui_activity_t* create_display_xpub_qr_activity(const uint32_t qr_flags)
{
    const bool use_format_hdkey = false; // qr_flags & QR_XPUB_HDKEY;  - not currently in use
    const char* const xpub_qr_format = use_format_hdkey ? BCUR_TYPE_CRYPTO_HDKEY : BCUR_TYPE_CRYPTO_ACCOUNT;
    const script_variant_t script_variant = xpub_script_variant_from_flags(qr_flags);
    const uint16_t account_index = qr_flags >> ACCOUNT_INDEX_FLAGS_SHIFT;

    // Deduce path based on script type and main/test network restrictions
    uint32_t path[EXPORT_XPUB_PATH_LEN]; // 3 or 4 - purpose'/cointype'/account'/[multisig bip48 script type']
    size_t path_len = 0;
    wallet_get_default_xpub_export_path(script_variant, account_index, path, EXPORT_XPUB_PATH_LEN, &path_len);

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
    const uint8_t qrcode_version = qr_version_from_flags(QR_DENSITY_LOW); // always use low density for xpub export
    bcur_create_qr_icons(cbor, written, xpub_qr_format, qrcode_version, &icons, &num_icons);

    // Create xpub activity for those icons
    char pathstr[MAX_PATH_STR_LEN(EXPORT_XPUB_PATH_LEN)];
    const bool ret = wallet_bip32_path_as_str(path, path_len, pathstr, sizeof(pathstr));
    JADE_ASSERT(ret);
    const char* label = contains_flags(qr_flags, QR_XPUB_MULTISIG) ? "Multisig" : "Singlesig";
    const uint8_t frames_per_qr = qr_framerate_from_flags(QR_SPEED_LOW); // always use slow framerate for xpub export
    return make_show_xpub_qr_activity(label, pathstr, icons, num_icons, frames_per_qr);
}

static bool handle_xpub_options(uint32_t* qr_flags)
{
    JADE_ASSERT(qr_flags);

    uint16_t account_index = (*qr_flags) >> ACCOUNT_INDEX_FLAGS_SHIFT;

    char buf[8];
    int rc = snprintf(buf, sizeof(buf), "%u", account_index);
    JADE_ASSERT(rc > 0 && rc < sizeof(buf));

    gui_view_node_t* script_item = NULL;
    gui_view_node_t* wallet_item = NULL;
    gui_view_node_t* account_item = NULL;
    gui_activity_t* const act = make_xpub_qr_options_activity(&script_item, &wallet_item, &account_item);
    update_menu_item(script_item, "Script", xpub_scripttype_desc_from_flags(*qr_flags));
    update_menu_item(wallet_item, "Wallet", xpub_wallettype_desc_from_flags(*qr_flags));
    update_menu_item(account_item, "Account Index", buf);
    gui_set_current_activity(act);

    gui_view_node_t* script_textbox = NULL;
    gui_activity_t* const act_scripttype = make_carousel_activity("Script Type", NULL, &script_textbox);
    gui_update_text(script_textbox, xpub_scripttype_desc_from_flags(*qr_flags));

    gui_view_node_t* wallet_textbox = NULL;
    gui_activity_t* const act_wallettype = make_carousel_activity("Wallet Type", NULL, &wallet_textbox);
    gui_update_text(wallet_textbox, xpub_wallettype_desc_from_flags(*qr_flags));

    gui_view_node_t* account_textbox = NULL;
    gui_activity_t* const act_account = make_carousel_activity("Account Index", NULL, &account_textbox);
    gui_update_text(account_textbox, buf);

    const uint32_t initial_flags = *qr_flags;
    while (true) {
        // Show, and await button click
        gui_set_current_activity(act);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_OPTIONS_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_XPUB_OPTIONS_SCRIPTTYPE) {
                gui_set_current_activity(act_scripttype);
                while (true) {
                    gui_update_text(script_textbox, xpub_scripttype_desc_from_flags(*qr_flags));
                    if (gui_activity_wait_event(act_scripttype, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                            rotate_flags(qr_flags, QR_XPUB_WITNESS, QR_XPUB_LEGACY);
                        } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            rotate_flags(qr_flags, QR_XPUB_LEGACY, QR_XPUB_WITNESS);
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(script_item, "Script", xpub_scripttype_desc_from_flags(*qr_flags));
            } else if (ev_id == BTN_XPUB_OPTIONS_WALLETTYPE) {
                gui_set_current_activity(act_wallettype);
                while (true) {
                    gui_update_text(wallet_textbox, xpub_wallettype_desc_from_flags(*qr_flags));
                    if (gui_activity_wait_event(act_wallettype, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT || ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            *qr_flags ^= QR_XPUB_MULTISIG; // toggle
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(wallet_item, "Wallet", xpub_wallettype_desc_from_flags(*qr_flags));
            } else if (ev_id == BTN_XPUB_OPTIONS_ACCOUNT) {
                gui_set_current_activity(act_account);
                while (true) {
                    rc = snprintf(buf, sizeof(buf), "%u", account_index);
                    JADE_ASSERT(rc > 0 && rc < sizeof(buf));
                    gui_update_text(account_textbox, buf);
                    if (gui_activity_wait_event(act_account, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                            // Avoid unsigned wrapping below zero
                            account_index = (account_index + ACCOUNT_INDEX_MAX - 1) % ACCOUNT_INDEX_MAX;
                        } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            account_index = (account_index + 1) % ACCOUNT_INDEX_MAX;
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(account_item, "Account Index", buf);
            } else if (ev_id == BTN_XPUB_OPTIONS_HELP) {
                await_qr_help_activity("blkstrm.com/xpub");
            } else if (ev_id == BTN_XPUB_OPTIONS_EXIT) {
                // Done
                break;
            }
        }
    }

    // If updated, persist prefereces
    *qr_flags = (uint16_t)(*qr_flags);
    *qr_flags |= (((uint32_t)account_index) << ACCOUNT_INDEX_FLAGS_SHIFT);
    if (initial_flags == *qr_flags) {
        return false;
    }

    // Return to indicate if any options were updated
    storage_set_qr_flags(*qr_flags);
    return true;
}

// Display xpub qr code
void display_xpub_qr(void)
{
    uint32_t qr_flags = storage_get_qr_flags();

    // Create show xpub activity for those icons
    gui_activity_t* act = create_display_xpub_qr_activity(qr_flags);

    while (true) {
        // Show, and await button click
        gui_set_current_activity(act);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_XPUB_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_XPUB_OPTIONS) {
                if (handle_xpub_options(&qr_flags)) {
                    // Options were updated - re-create xpub screen
                    act = create_display_xpub_qr_activity(qr_flags);
                }
            } else if (ev_id == BTN_XPUB_HELP) {
                await_qr_help_activity("blkstrm.com/xpub");
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
    gui_view_node_t* item_text = NULL;
    gui_activity_t* const act = make_carousel_activity("Select Wallet", NULL, &item_text);
    JADE_ASSERT(item_text);
    gui_set_current_activity(act);

    const size_t limit = num_names + 1;
    while (true) {
        JADE_ASSERT(*selected < limit);
        gui_update_text(item_text, *selected < num_names ? names[*selected] : "[Cancel]");

        // wait for a GUI event
        int32_t ev_id = 0;
        gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

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

// Get search root for singlesig address
static void get_singlesig_search_root(const script_variant_t variant, const uint16_t account_index,
    const bool is_change, char* pathstr, const size_t pathstr_len, struct ext_key* search_roots,
    const size_t search_roots_len)
{
    JADE_ASSERT(pathstr);
    JADE_ASSERT(pathstr_len);
    JADE_ASSERT(search_roots);
    JADE_ASSERT(search_roots_len == 1);

    // Get the path to search
    size_t path_len = 0;
    uint32_t path[EXPORT_XPUB_PATH_LEN];
    wallet_get_default_xpub_export_path(variant, account_index, path, EXPORT_XPUB_PATH_LEN, &path_len);
    JADE_ASSERT(path_len == EXPORT_XPUB_PATH_LEN - 1);
    path[path_len++] = is_change ? 1 : 0; // set change indicator

    // Get as hdkey
    bool ret = wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, search_roots);
    JADE_ASSERT(ret);

    // Use the root bip32 path as the label
    ret = wallet_bip32_path_as_str(path, path_len, pathstr, pathstr_len);
    JADE_ASSERT(ret);
}

// Get search root for multisig address
static void get_multisig_search_roots(const multisig_data_t* multisig_data, const bool is_change, char* pathstr,
    const size_t pathstr_len, struct ext_key* search_roots, const size_t search_roots_len)
{
    JADE_ASSERT(multisig_data);
    JADE_ASSERT(pathstr);
    JADE_ASSERT(pathstr_len);
    JADE_ASSERT(search_roots);
    JADE_ASSERT(search_roots_len);
    JADE_ASSERT(search_roots_len == multisig_data->num_xpubs);

    // Derive set of multisig parent keys
    const uint32_t path[] = { is_change ? 1 : 0 }; // set change indicator
    for (int i = 0; i < search_roots_len; ++i) {
        const uint8_t* xpub = multisig_data->xpubs + (i * BIP32_SERIALIZED_LEN);
        const bool ret = wallet_derive_pubkey(
            xpub, BIP32_SERIALIZED_LEN, path, 1, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &search_roots[i]);
        JADE_ASSERT(ret);
    }

    // Use the existing name plus the change indicator as the label
    const size_t len = strlen(pathstr);
    JADE_ASSERT(len < pathstr_len);
    JADE_ASSERT(pathstr[len - 1] == '0' || pathstr[len - 1] == '1');
    pathstr[len - 1] = is_change ? '1' : '0';
}

static bool handle_address_options(const bool show_account, uint16_t* account_index, bool* is_change)
{
    JADE_ASSERT(account_index || !show_account);
    JADE_ASSERT(is_change);

    // Create the 'options' screens
    char buf[8];
    gui_view_node_t* account_item = NULL;
    gui_view_node_t* change_item = NULL;
    gui_activity_t* const act_options = make_search_address_options_activity(show_account, &account_item, &change_item);
    JADE_ASSERT(!account_item == !show_account);

    gui_activity_t* act_account = NULL;
    gui_view_node_t* account_textbox = NULL;
    if (account_item) {
        const int ret = snprintf(buf, sizeof(buf), "%u", *account_index);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
        update_menu_item(account_item, "Account Index", buf);

        act_account = make_carousel_activity("Account Index", NULL, &account_textbox);
        gui_update_text(account_textbox, buf);
    }
    update_menu_item(change_item, "Change", *is_change ? "Yes" : "No");

    const bool initial_change = *is_change;
    const uint16_t initial_account = *account_index;
    while (true) {
        int32_t ev_id;
        gui_set_current_activity(act_options);
        if (gui_activity_wait_event(act_options, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {

            if (ev_id == BTN_SCAN_ADDRESS_OPTIONS_ACCOUNT) {
                gui_set_current_activity(act_account);
                while (true) {
                    const int ret = snprintf(buf, sizeof(buf), "%u", *account_index);
                    JADE_ASSERT(ret > 0 && ret < sizeof(buf));
                    gui_update_text(account_textbox, buf);
                    if (gui_activity_wait_event(act_account, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                            // Avoid unsigned wrapping below zero
                            *account_index = (*account_index + ACCOUNT_INDEX_MAX - 1) % ACCOUNT_INDEX_MAX;
                        } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            *account_index = (*account_index + 1) % ACCOUNT_INDEX_MAX;
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(account_item, "Account Index", buf);
            } else if (ev_id == BTN_SCAN_ADDRESS_OPTIONS_CHANGE) {
                // Simple toggle
                *is_change = !*is_change;
                update_menu_item(change_item, "Change", *is_change ? "Yes" : "No");
            } else if (ev_id == BTN_SCAN_ADDRESS_OPTIONS_EXIT) {
                // Exit optins screen
                break;
            }
        }
    }

    // Return value indicates whether options were changed
    return *is_change != initial_change || *account_index != initial_account;
}

// Verify an address string by brute-forcing
static bool verify_address(const address_data_t* const addr_data)
{
    JADE_ASSERT(addr_data);

    JADE_ASSERT(addr_data->network);
    JADE_ASSERT(addr_data->script_len);

    const bool default_selection = true;
    if (!show_confirm_address_activity(addr_data->address, default_selection)) {
        // Abandon
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

    char label[MAX_PATH_STR_LEN(EXPORT_XPUB_PATH_LEN)];
    script_variant_t variant;
    uint16_t account_index = 0;
    multisig_data_t* multisig_data = NULL;
    bool is_change = false;
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
            || await_yesno_activity(
                "Verify Address", "     Are you trying to\n     verify a multisig\n           address?", false, NULL)) {
            // Must have a multisig record - user to select
            size_t selected = 0;
            if (!num_multisigs || !select_multisig_record(names, num_multisigs, &selected)) {
                JADE_LOGE("No relevant multisig records found/selected for multisig address");
                await_error_activity("\nRegister multisig record\n  before attempting to\n      verify a multisig\n    "
                                     "        address");
                return false;
            }
            JADE_ASSERT(selected < num_multisigs);

            const char* errmsg = NULL;
            multisig_data = JADE_MALLOC(sizeof(multisig_data_t));
            if (!multisig_load_from_storage(names[selected], multisig_data, NULL, 0, NULL, &errmsg)) {
                await_error_activity("Failed to load multisig record");
                free(multisig_data);
                return false;
            }

            // Use the multisig name plus the change indicator as the label
            const int ret = snprintf(label, sizeof(label), "%s/%u", names[selected], is_change ? 1 : 0);
            JADE_ASSERT(ret > 0 && ret < sizeof(label));

            // Calculate the key search roots (ie. up to the final leaf)
            search_roots_len = multisig_data->num_xpubs;
            search_roots = JADE_CALLOC(search_roots_len, sizeof(struct ext_key));
            get_multisig_search_roots(multisig_data, is_change, label, sizeof(label), search_roots, search_roots_len);
        }
    }

    // If not multisig, must be singlesig
    if (!multisig_data) {
        JADE_ASSERT(!search_roots);
        JADE_ASSERT(!search_roots_len);

        if (!get_singlesig_variant_from_script_type(script_type, &variant)) {
            await_error_activity("Address scriptpubkey unsupported");
            return false;
        }

        // Default search root account to the last exported xpub
        const uint32_t qr_flags = storage_get_qr_flags();
        account_index = qr_flags >> ACCOUNT_INDEX_FLAGS_SHIFT;

        // Calculate the key search root (ie. up to the final leaf)
        search_roots_len = 1;
        search_roots = JADE_CALLOC(search_roots_len, sizeof(struct ext_key));
        get_singlesig_search_root(
            variant, account_index, is_change, label, sizeof(label), search_roots, search_roots_len);
    }

    // Create the main search progress screen
    gui_view_node_t* label_text = NULL;
    gui_view_node_t* index_text = NULL;
    progress_bar_t progress_bar = {};
    gui_activity_t* const act = make_search_verify_address_activity(label, &label_text, &progress_bar, &index_text);
    JADE_ASSERT(label_text);
    JADE_ASSERT(index_text);

    // Make an event-data structure to track events - attached to the activity
    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(act);
    JADE_ASSERT(event_data);

    // ... and register against the activity - we will await btn events later
    gui_activity_register_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    size_t index = 0;
    size_t confirmed_at_index = index;
    bool verified = false;
    const size_t address_search_batch_size = ADDRESS_SEARCH_BATCH_SIZE(multisig_data);
    const size_t num_indexes_to_reconfirm = NUM_INDEXES_TO_RECONFIRM(multisig_data);
    while (!verified) {
        gui_set_current_activity(act);

        // Update the progress bar and text label
        char idx_txt[12];
        const int ret = snprintf(idx_txt, sizeof(idx_txt), "%u", index);
        JADE_ASSERT(ret > 0 && ret < sizeof(idx_txt));
        update_progress_bar(&progress_bar, num_indexes_to_reconfirm, index - confirmed_at_index);
        gui_update_text(index_text, idx_txt);

        // Search a small batch of paths for the address script
        // NOTE: 'index' is updated as we go along
        JADE_ASSERT(search_roots);
        if (multisig_data) {
            verified = wallet_search_for_multisig_script(multisig_data->variant, multisig_data->sorted,
                multisig_data->threshold, search_roots, search_roots_len, &index, address_search_batch_size,
                addr_data->script, addr_data->script_len);
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
            char buf[64];
            const int ret = snprintf(
                buf, sizeof(buf), "\n Failed to verify, check\n   next %u addresses?", num_indexes_to_reconfirm);
            JADE_ASSERT(ret > 0 && ret < sizeof(buf));
            if (!await_yesno_activity("Verify Address", buf, true, "blkstrm.com/scanaddress")) {
                // Abandon - exit loop
                break;
            }
            confirmed_at_index = index;
        } else {
            // Giver user a chance to exit or to skip this batch of addresses
            int32_t ev_id = 0;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
            const bool ret = sync_wait_event(event_data, NULL, &ev_id, NULL, 10 / portTICK_PERIOD_MS) == ESP_OK;
#else
            sync_wait_event(event_data, NULL, NULL, NULL, CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
            const bool ret = index > 4 * num_indexes_to_reconfirm; // let it run for a few batches, then exit
            ev_id = BTN_SCAN_ADDRESS_EXIT;
#endif
            if (ret) {
                if (ev_id == BTN_SCAN_ADDRESS_SKIP_ADDRESSES) {
                    // Jump to end of this batch
                    index = confirmed_at_index + num_indexes_to_reconfirm;
                    confirmed_at_index = index;
                } else if (ev_id == BTN_SCAN_ADDRESS_OPTIONS) {
                    if (handle_address_options(!multisig_data, &account_index, &is_change)) {
                        // Recreate the search root(s) and update the screen label
                        if (multisig_data) {
                            get_multisig_search_roots(
                                multisig_data, is_change, label, sizeof(label), search_roots, search_roots_len);
                        } else {
                            get_singlesig_search_root(variant, account_index, is_change, label, sizeof(label),
                                search_roots, search_roots_len);
                        }
                        gui_update_text(label_text, label);

                        // Restart search from index 0
                        confirmed_at_index = 0;
                        index = 0;
                    }
                } else if (ev_id == BTN_SCAN_ADDRESS_EXIT) {
                    // Abandon - exit loop
                    break;
                }
            }
        }
    }

    if (verified) {
        char buf[64];
        const int ret = snprintf(buf, sizeof(buf), "\n\n Address verified:\n  %s/%u", label, index);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
        await_message_activity(buf);
    } else {
        await_error_activity("Address NOT verified!");
    }

    free(multisig_data);
    free(search_roots);
    return verified;
}

// Handle QR Options dialog - ie. QR size and frame-rate
static bool handle_qr_options(uint32_t* qr_flags)
{
    JADE_ASSERT(qr_flags);

    gui_view_node_t* density_item = NULL;
    gui_view_node_t* framerate_item = NULL;
    gui_activity_t* const act = make_qr_options_activity(&density_item, &framerate_item);
    update_menu_item(density_item, "QR Density", qr_density_desc_from_flags(*qr_flags));
    update_menu_item(framerate_item, "Frame Rate", qr_framerate_desc_from_flags(*qr_flags));

    gui_view_node_t* density_textbox = NULL;
    gui_activity_t* const act_density = make_carousel_activity("QR Density", NULL, &density_textbox);
    gui_update_text(density_textbox, qr_density_desc_from_flags(*qr_flags));

    gui_view_node_t* framerate_textbox = NULL;
    gui_activity_t* const act_framerate = make_carousel_activity("Frame Rate", NULL, &framerate_textbox);
    gui_update_text(framerate_textbox, qr_framerate_desc_from_flags(*qr_flags));

    const uint32_t initial_flags = *qr_flags;
    while (true) {
        // Show, and await button click
        gui_set_current_activity(act);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_QR_OPTIONS_EXIT;
#endif
        if (ret) {
            // NOTE: For Density and Speed :- HIGH|LOW > HIGH > LOW
            // Rotate through: LOW -> HIGH -> HIGH|LOW -> LOW -> ...
            // unset/default is treated as HIGH ie. the middle value
            if (ev_id == BTN_QR_OPTIONS_DENSITY) {
                gui_set_current_activity(act_density);
                while (true) {
                    gui_update_text(density_textbox, qr_density_desc_from_flags(*qr_flags));
                    if (gui_activity_wait_event(act_density, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                            rotate_flags(qr_flags, QR_DENSITY_LOW, QR_DENSITY_HIGH); // reverse
                        } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            rotate_flags(qr_flags, QR_DENSITY_HIGH, QR_DENSITY_LOW);
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(density_item, "QR Density", qr_density_desc_from_flags(*qr_flags));
            } else if (ev_id == BTN_QR_OPTIONS_FRAMERATE) {
                gui_set_current_activity(act_framerate);
                while (true) {
                    gui_update_text(framerate_textbox, qr_framerate_desc_from_flags(*qr_flags));
                    if (gui_activity_wait_event(act_framerate, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                            rotate_flags(qr_flags, QR_SPEED_LOW, QR_SPEED_HIGH); // reverse
                        } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            rotate_flags(qr_flags, QR_SPEED_HIGH, QR_SPEED_LOW);
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(framerate_item, "Frame Rate", qr_framerate_desc_from_flags(*qr_flags));
            } else if (ev_id == BTN_QR_OPTIONS_HELP) {
                await_qr_help_activity("blkstrm.com/scanjade");
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
static gui_activity_t* create_display_bcur_qr_activity(const char* label, const char* bcur_type, const uint8_t* cbor,
    const size_t cbor_len, const uint32_t qr_flags, const char* help_url)
{
    JADE_ASSERT(label);
    JADE_ASSERT(bcur_type);
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);
    // help_url is optional

    // Map BCUR cbor into a series of QR-code icons
    Icon* icons = NULL;
    size_t num_icons = 0;
    const uint8_t qrcode_version = qr_version_from_flags(qr_flags);
    bcur_create_qr_icons(cbor, cbor_len, bcur_type, qrcode_version, &icons, &num_icons);

    // Create qr activity for those icons
    const bool show_options_button = true;
    const uint8_t frames_per_qr = qr_framerate_from_flags(qr_flags);
    return make_show_qr_activity(label, icons, num_icons, frames_per_qr, show_options_button, help_url);
}

// Display a QR code, with access to size_speed options
static void display_bcur_qr(
    const char* label, const char* bcur_type, const uint8_t* cbor, const size_t cbor_len, const char* help_url)
{
    JADE_ASSERT(label);
    JADE_ASSERT(bcur_type);
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);
    // help_url is optional

    uint32_t qr_flags = storage_get_qr_flags();

    // When displaying a bcur qr code we set the minimum idle timeout to keep the hw from sleeping too quickly
    // (If the user has set a longer timeout value that is respected)
    idletimer_set_min_timeout_secs(BCUR_QR_DISPLAY_MIN_TIMEOUT_SECS);

    // Create show psbt activity for those icons
    gui_activity_t* act = create_display_bcur_qr_activity(label, bcur_type, cbor, cbor_len, qr_flags, help_url);

    while (true) {
        // Show, and await button click
        gui_set_current_activity(act);

        int32_t ev_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_QR_DISPLAY_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_QR_OPTIONS) {
                if (handle_qr_options(&qr_flags)) {
                    // Options were updated - re-create psbt qr screen
                    display_processing_message_activity();
                    act = create_display_bcur_qr_activity(label, bcur_type, cbor, cbor_len, qr_flags, help_url);
                }
            } else if (ev_id == BTN_QR_DISPLAY_HELP) {
                await_qr_help_activity(help_url);
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

    // Try to handle as 'sign message' (specter format)
    if (bytes_len > sizeof("signmessage") && !strncasecmp(strbytes, "signmessage", sizeof("signmessage") - 1)) {
        // Looks like a 'signmessage' qr

        uint8_t sig[EC_SIGNATURE_LEN * 2]; // Sufficient
        size_t written = 0;
        const char* errmsg = NULL;
        const int errcode = sign_message_file(strbytes, bytes_len, sig, sizeof(sig), &written, &errmsg);
        if (errcode) {
            if (errcode != CBOR_RPC_USER_CANCELLED) {
                JADE_LOGE("Processing 'signmessage' QR failed: %d, %s", errcode, errmsg);
                await_error_activity(errmsg);
            }
            return false;
        }
        JADE_ASSERT(written);
        JADE_ASSERT(written < sizeof(sig));
        JADE_ASSERT(sig[written - 1] == '\0');

        await_single_qr_activity("Scan QR\nsignature", sig, written - 1, NULL);
        return true;
    }

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
            if (errcode != CBOR_RPC_USER_CANCELLED) {
                JADE_LOGE("Processing multisig file failed: %s", errmsg);
                await_error_activity(errmsg);
            }
            return false;
        }
        return true;
    }

    // See if it looks like a new wallet phrase
    // NOTE: these must always be nul-terminated (even when a binary compact seed qr)
    if (strbytes[bytes_len] == '\0') {
        char mnemonic[MNEMONIC_BUFLEN];
        SENSITIVE_PUSH(mnemonic, sizeof(mnemonic));
        size_t written = 0;
        if (import_mnemonic(bytes, bytes_len, mnemonic, sizeof(mnemonic), &written) && written < sizeof(mnemonic)) {
            if (!handle_mnemonic_qr(mnemonic)) {
                JADE_LOGE("Handling new scanned mnemonic failed");
                await_error_activity("Failed loading wallet");
                SENSITIVE_POP(mnemonic);
                return false;
            }
            SENSITIVE_POP(mnemonic);
            return true;
        }
        SENSITIVE_POP(mnemonic);
    }

    JADE_LOGW("Unhandled QR (bytes) message");
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
    const char* network = keychain_get_network_type_restriction() == NETWORK_TYPE_TEST ? TAG_TESTNET : TAG_MAINNET;
    const int errcode = sign_psbt(network, psbt, &errmsg);
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
    display_bcur_qr(
        "Scan with\n   wallet\n     app", BCUR_TYPE_CRYPTO_PSBT, cbor_signed, cbor_signed_len, "blkstrm.com/psbt");

cleanup:
    JADE_WALLY_VERIFY(wally_psbt_free(psbt));
    return ret;
}

static bool handle_bip85_bip39_request_qr(const uint8_t* cbor, const size_t cbor_len)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);

    // Parse cbor
    CborValue root;
    CborParser parser;
    if (!bcur_parse_jade_message(cbor, cbor_len, &parser, &root, NULL, NULL)) {
        JADE_LOGE("Failed to parse Jade bip85/bip39 entropy request");
        await_error_activity("Error parsing message");
        return false;
    }

    uint8_t cbor_reply[176]; // sufficient
    CborEncoder reply_encoder;
    cbor_encoder_init(&reply_encoder, cbor_reply, sizeof(cbor_reply), 0);

    const char* errmsg = NULL;
    const int errcode = get_bip85_bip39_entropy_cbor(&root, &reply_encoder, &errmsg);
    if (errcode) {
        if (errcode != CBOR_RPC_USER_CANCELLED) {
            JADE_LOGE("Error generating encrypted bip85 entropy: %s", errmsg);
            char buf[128];
            const int ret = snprintf(buf, sizeof(buf), "Error in bip85/bip39\n%s", errmsg);
            JADE_ASSERT(ret > 0 && ret < sizeof(buf));
            await_error_activity(buf);
        }
        return false;
    }

    const size_t reply_cbor_len = cbor_encoder_get_buffer_size(&reply_encoder, cbor_reply);
    JADE_ASSERT(reply_cbor_len && reply_cbor_len <= sizeof(cbor_reply));

    // Now display bcur QR
    display_bcur_qr("Scan with\n   wallet\n     app", BCUR_TYPE_JADE_BIP8539_REPLY, cbor_reply, reply_cbor_len,
        "blkstrm.com/bip85");

    return true;
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
    const int ret = snprintf(msg, sizeof(msg), "Time set successfully\n%s", timestr);
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
        await_error_activity("Error parsing Oracle data");
        return false;
    }

    const char* errmsg = NULL;
    const int errcode = update_pinserver(&params, &errmsg);
    if (errcode) {
        if (errcode != CBOR_RPC_USER_CANCELLED) {
            JADE_LOGE("Error updating pinserver details: %s", errmsg);
            char buf[128];
            const int ret = snprintf(buf, sizeof(buf), "Error updating Oracle\n%s", errmsg);
            JADE_ASSERT(ret > 0 && ret < sizeof(buf));
            await_error_activity(buf);
        }
        return false;
    }
    return true;
}

static bool handle_bip39_qr(const uint8_t* cbor, const size_t cbor_len)
{
    char mnemonic[MNEMONIC_BUFLEN];
    SENSITIVE_PUSH(mnemonic, sizeof(mnemonic));
    size_t written = 0;
    if (!bcur_parse_bip39(cbor, cbor_len, mnemonic, sizeof(mnemonic), &written) || written >= sizeof(mnemonic)
        || !handle_mnemonic_qr(mnemonic)) {
        SENSITIVE_POP(mnemonic);
        JADE_LOGE("Processing scanned mnemonic data failed");
        await_error_activity("Failed loading wallet");
        return false;
    }

    SENSITIVE_POP(mnemonic);
    return true;
}

// Handle scanning a QR - supports addresses and PSBTs
void handle_scan_qr(void)
{
    // Scan QR - potentially a BC-UR/multi-frame QR
    char* type = NULL;
    uint8_t* data = NULL;
    size_t data_len = 0;
    if (!bcur_scan_qr("     Scan\n supported\n  QR code", &type, &data, &data_len, "blkstrm.com/jadescan") || !data) {
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
        } else if (!strcasecmp(type, BCUR_TYPE_JADE_BIP8539_REQUEST)) {
            // BIP85/BIP39 entropy request
            if (!handle_bip85_bip39_request_qr(data, data_len)) {
                JADE_LOGE("Processing BC-UR as bip85/bip39 entropy request failed");
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
        } else if (!strcasecmp(type, BCUR_TYPE_CRYPTO_BIP39)) {
            // BIP39 phrase
            if (!handle_bip39_qr(data, data_len)) {
                JADE_LOGE("Processing BC-UR as bip39 phrase failed");
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
            JADE_LOGW("Unhandled QR (as bytes) message");
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

// Display a BC-UR bytes message
bool display_bcur_bytes_qr(const char* label, const uint8_t* data, const size_t data_len, const char* help_url)
{
    JADE_ASSERT(label);
    JADE_ASSERT(data);
    JADE_ASSERT(data_len);

    // Build BCUR message holding the bytes
    uint8_t* cbor = NULL;
    size_t cbor_len = 0;
    if (!bcur_build_cbor_bytes(data, data_len, &cbor, &cbor_len)) {
        JADE_LOGW("Failed to build cbor bytes message");
        return false;
    }

    // Now display bcur QR
    display_bcur_qr(label, BCUR_TYPE_BYTES, cbor, cbor_len, help_url);

    free(cbor);
    return true;
}

// Display screen with help url and qr code
// Handles up to v6. codes - ie text up to 134 bytes
// help_url is optional
void await_single_qr_activity(const char* label, const uint8_t* data, const size_t data_len, const char* help_url)
{
    JADE_ASSERT(label);
    JADE_ASSERT(data);
    JADE_ASSERT(data_len);
    // help_url is optional

    const bool large_icons = true;
    Icon* const qr_icon = JADE_MALLOC(sizeof(Icon));
    bytes_to_qr_icon(data, data_len, large_icons, qr_icon);

    // Show, and await button click - note gui takes ownership of icon
    gui_activity_t* const act = make_show_qr_activity(label, qr_icon, 1, 0, false, help_url);
    int32_t ev_id;

    while (true) {
        gui_set_current_activity(act);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_QR_DISPLAY_EXIT, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_QR_DISPLAY_EXIT;
#endif

        if (ret) {
            if (ev_id == BTN_QR_DISPLAY_EXIT) {
                // Done
                break;
            } else if (ev_id == BTN_QR_DISPLAY_HELP) {
                await_qr_help_activity(help_url);
            }
        }
    }
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
    gui_activity_t* const act = make_show_qr_help_activity(url, qr_icon);
    gui_set_current_activity(act);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_QR_HELP_EXIT, NULL, NULL, NULL, 0);
#else
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_QR_HELP_EXIT, NULL, NULL, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
#endif
}

// Display screen with help url and qr code
bool await_qr_back_continue_activity(const char* label, const char* url, const bool default_selection)
{
    JADE_ASSERT(label);
    JADE_ASSERT(url);

    const size_t url_len = strlen(url);
    JADE_ASSERT(url_len < 78); // v4, binary

    const bool large_icons = false;
    Icon* const qr_icon = JADE_MALLOC(sizeof(Icon));
    bytes_to_qr_icon((const uint8_t*)url, url_len, large_icons, qr_icon);

    // Show, and await button click
    gui_activity_t* const act = make_qr_back_continue_activity(label, url, qr_icon, default_selection);
    gui_set_current_activity(act);

    int32_t ev_id = 0;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool ret = true;
    ev_id = BTN_YES;
#endif

    // Return whether 'Continue' was cicked
    return ret && ev_id == BTN_YES;
}

// QR-Mode PinServer interaction

// Post a message onto Jade's input queue
static bool post_in_message(const uint8_t* msg, const size_t msg_len, const jade_msg_source_t source)
{
    JADE_ASSERT(msg);
    JADE_ASSERT(msg_len);

    // Post as message into Jade with msg-source prefix
    const size_t fullmsg_len = msg_len + 1;
    uint8_t* const fullmsg = JADE_MALLOC(fullmsg_len);
    fullmsg[0] = source;
    memcpy(fullmsg + 1, msg, msg_len);
    const bool ret = jade_process_push_in_message(fullmsg, fullmsg_len);
    free(fullmsg);
    return ret;
}

// Create and post a 'cancel' message
static bool post_cancel_message(const jade_msg_source_t source)
{
    uint8_t cbor_buf[32];
    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, cbor_buf, sizeof(cbor_buf), 0);

    CborEncoder root_map_encoder; // id, method
    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);
    add_string_to_map(&root_map_encoder, "id", "qrcancel");
    add_string_to_map(&root_map_encoder, "method", "cancel");
    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    return post_in_message(cbor_buf, cbor_len, source);
}

// Locally create and post an 'auth_user' request
static bool post_auth_msg_request(const jade_msg_source_t source)
{
    uint8_t cbor_buf[64];
    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, cbor_buf, sizeof(cbor_buf), 0);

    CborEncoder root_map_encoder; // id, method, params
    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);
    add_string_to_map(&root_map_encoder, "id", "qrauth");
    add_string_to_map(&root_map_encoder, "method", "auth_user");

    // Add parameters (ie. network)
    cberr = cbor_encode_text_stringz(&root_map_encoder, "params");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder params_encoder; // network
    cberr = cbor_encoder_create_map(&root_map_encoder, &params_encoder, 1);
    JADE_ASSERT(cberr == CborNoError);
    const network_type_t restriction = keychain_get_network_type_restriction();
    const char* networks = restriction == NETWORK_TYPE_TEST ? "testnet" : "mainnet";
    add_string_to_map(&params_encoder, "network", networks);
    cberr = cbor_encoder_close_container(&root_map_encoder, &params_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);

    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, cbor_buf);
    return post_in_message(cbor_buf, cbor_len, source);
}

// Scan a bcur QR code, and post it into Jade with SOURCE_QR
static bool scan_qr_post_in_message(const char* label, const char* expected_type)
{
    JADE_ASSERT(label);
    JADE_ASSERT(expected_type);

    char* output_type = NULL;
    uint8_t* output = NULL;
    size_t output_len = 0;
    bool ret = false;

    // NOTE: we take ownership of 'output_type' and 'output'
    if (!bcur_scan_qr(label, &output_type, &output, &output_len, "blkstrm.com/qrpin")) {
        JADE_LOGI("QR scanning failed or abandoned");
        return false;
    }

    // Check if a non-bc-ur code frame was scanned
    if (!output_type) {
        JADE_LOGW("Scanning encountered a non-BC-UR QR code, when expecting BC-UR type %s", expected_type);
        await_error_activity("Unexpected QR payload");
        goto cleanup;
    }

    // Check the type is as expected
    if (strcasecmp(expected_type, output_type)) {
        JADE_LOGW("Scanning returned unexpected type %s when expecting %s", output_type, expected_type);
        await_error_activity("Unexpected QR payload type");
        goto cleanup;
    }

    // Post as message into Jade with source-qr prefix
    ret = post_in_message(output, output_len, SOURCE_QR);

cleanup:
    free(output);
    free(output_type);
    return ret;
}

// NOTE: this 'writer' callback must return true to indicate that it has taken the message
// (whether valid/expected or not), and it does not want to wait to be presented with another message.
// ie. the return indicates processing has finished, not that processing was necessarily successful.
// (That information is returned in the context object.)
// NOTE: the presence of a 'label' indicates we want to display the message payload as a QR
static bool handle_pinserver_reply(const char* label, const uint8_t* msg, const size_t len, void* ctx)
{
    // label is optional
    JADE_ASSERT(msg);
    JADE_ASSERT(len);
    JADE_ASSERT(ctx);

    bool* const ok = (bool*)ctx;
    *ok = false;

    // Parse the received message
    CborParser parser;
    CborValue message;
    const CborError cberr = cbor_parser_init(msg, len, CborValidateBasic, &parser, &message);
    if (cberr != CborNoError || !rpc_message_valid(&message)) {
        JADE_LOGE("Invalid cbor message");
        goto cleanup;
    }

    // Ultimate response is boolean
    bool bool_result = false;
    if (rpc_get_boolean("result", &message, &bool_result)) {
        JADE_LOGI("PIN QR result: %u", bool_result);
        goto cleanup;
    }

    CborValue result;
    CborValue http_request;
    if (!rpc_get_map("result", &message, &result) || !rpc_get_map("http_request", &result, &http_request)) {
        JADE_LOGE("Unexpected cbor message - no 'http_request' result payload");
        goto cleanup;
    }

    // Display message as bcur qr if a screen label was passed
    if (label) {
        display_bcur_qr(label, BCUR_TYPE_JADE_PIN, msg, len, "blkstrm.com/qrpin");
    }

    // Message received and QR displayed successfully
    *ok = true;

cleanup:
    // We return true in all cases to indicate that a message was received
    // and we should stop waiting - whether the message was processed 'successfully'
    // is indicated by the 'ok' flag in the passed context object.
    return true;
}

static bool handle_first_pinserver_reply(const uint8_t* msg, const size_t len, void* ctx)
{
    return handle_pinserver_reply(" Step 1/4\nScan Jade\n     QR", msg, len, ctx);
}

static bool handle_second_pinserver_reply(const uint8_t* msg, const size_t len, void* ctx)
{
    return handle_pinserver_reply(" Step 3/4\nScan Jade\n     QR", msg, len, ctx);
}

static bool handle_third_pinserver_reply(const uint8_t* msg, const size_t len, void* ctx)
{
    // No QR to display with final reply
    return handle_pinserver_reply(NULL, msg, len, ctx);
}

static bool get_outbound_reply_show_qr(outbound_message_writer_fn_t handler)
{
    JADE_ASSERT(handler);

    // Await message from Jade to pinserver
    bool ok = false;
    while (!jade_process_get_out_message(handler, SOURCE_QR, &ok)) {
        // Await outbound message
    }
    return ok;
}

// This task is run to act as a client to Jade's normal 'auth-user' processing
static void auth_qr_client_task(void* unused)
{
    JADE_LOGI("Starting Auth QR client task: %d", xPortGetFreeHeapSize());

    // Only needed/expected for 'full' inititialistion with pinserver
    JADE_ASSERT(!keychain_has_temporary());

    // Drain any old messages sitting on the QR queue
    while (jade_process_get_out_message(NULL, SOURCE_QR, NULL)) {
        JADE_LOGW("Discarded stale message from QR queue");
    }

    // Post in a synthesized 'auth_user' message
    JADE_LOGI("Posting initial auth_user message");
    if (!post_auth_msg_request(SOURCE_QR)) {
        JADE_LOGW("Failed to post initial auth_user message");
        goto cleanup;
    }

    // Wait for message (from synthesized auth_user/pinclient processing)
    // and display the message payload as bcur QR code on screen.
    JADE_LOGI("Awaiting auth_user reply data to display as qr");
    if (!get_outbound_reply_show_qr(handle_first_pinserver_reply)) {
        JADE_LOGW("Failed to receive auth_user reply data");
        goto cleanup;
    }

    // Scan qr code and post back to auth_user/pinclient task
    // 'start_handshake'
    JADE_LOGI("Scanning/posting start_handshake data");
    if (!scan_qr_post_in_message("  Step 2/4\n Scan Web\n      QR", BCUR_TYPE_JADE_PIN)) {
        JADE_LOGW("Failed to scan start_handshake message");
        goto cleanup;
    }

    // Wait for message from auth_user/pinclient processing
    // and display as bcur QR code on screen
    JADE_LOGI("Awaiting start_handshake reply data to display as qr");
    if (!get_outbound_reply_show_qr(handle_second_pinserver_reply)) {
        JADE_LOGW("Failed to receive start_handshake reply data");
        goto cleanup;
    }

    // Scan qr code and post back to auth_user/pinclient task
    // 'handshake_complete'
    JADE_LOGI("Scanning/posting handshake_complete data");
    if (!scan_qr_post_in_message("  Step 4/4\n Scan Web\n      QR", BCUR_TYPE_JADE_PIN)) {
        JADE_LOGW("Failed to scan handshake_complete message");
        goto cleanup;
    }

    // Process (discard) the final message
    JADE_LOGI("Awaiting (discarding) handshake_complete reply data");
    get_outbound_reply_show_qr(handle_third_pinserver_reply);

    JADE_LOGI("Success");

cleanup:
    // Post a cancel message which should ensure the main dashboard task returns
    // (it will be ignored if not required)
    post_cancel_message(SOURCE_QR);

    // Log the task stack HWM so we can estimate ideal stack size
    JADE_LOGI("Auth QR client task complete - task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));

    // Delete this task
    vTaskDelete(NULL);
}

void handle_qr_auth(void)
{
    // Only needed/expected for 'full' inititialistion with pinserver
    JADE_ASSERT(!keychain_has_temporary());

    // Start a task to run the qr client side
    TaskHandle_t auth_qr_client_task_handle;
    const BaseType_t retval = xTaskCreatePinnedToCore(&auth_qr_client_task, "auth_qr_client_task", 4 * 1024, NULL,
        JADE_TASK_PRIO_GUI, &auth_qr_client_task_handle, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create auth_qr_client_task, xTaskCreatePinnedToCore() returned %d", retval);

    // Then we return to the dispatcher to handle messages as sent by the task we have just started
}
