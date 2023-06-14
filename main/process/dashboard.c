#include <esp_ota_ops.h>

#include <ctype.h>

#include "../bcur.h"
#include "../button_events.h"
#include "../display.h"
#include "../input.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../otpauth.h"
#include "../power.h"
#include "../process.h"
#include "../qrmode.h"
#include "../random.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../utils/util.h"
#include "../utils/wally_ext.h"
#include "../wallet.h"
#ifdef CONFIG_BT_ENABLED
#include "../ble/ble.h"
#else
// Stubs
static inline bool ble_enabled(void) { return false; }
static inline bool ble_connected(void) { return false; }
static inline void ble_start(void) { JADE_ASSERT(false); }
#endif
#include "process/ota_defines.h"
#include "process_utils.h"

#include <esp_chip_info.h>
#include <esp_mac.h>
#include <sodium/utils.h>
#include <time.h>

// Whether during initialisation we select USB, BLE QR etc.
static jade_msg_source_t initialisation_source = SOURCE_NONE;
static bool show_connect_screen = false;

// The dynamic home screen menu
#define HOME_SCREEN_TYPE_UNINIT 0
#define HOME_SCREEN_TYPE_LOCKED 1
#define HOME_SCREEN_TYPE_ACTIVE 2
#define HOME_SCREEN_TYPE_NUM_STATES 3

static uint8_t home_screen_type = 0;
static uint8_t home_screen_menu_item = 0;
gui_view_node_t* home_screen_item_symbol = NULL;
gui_view_node_t* home_screen_item_text = NULL;

typedef struct {
    const char* symbol;
    const char* text;
    const uint32_t btn_id;
} home_menu_item_t;

// Menus for the HOME_SCREEN_TYPE_XXX values above
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
#define NUM_HOME_SCREEN_MENU_ENTRIES 3
#else
#define NUM_HOME_SCREEN_MENU_ENTRIES 2
#endif

home_menu_item_t home_menu_items[HOME_SCREEN_TYPE_NUM_STATES][NUM_HOME_SCREEN_MENU_ENTRIES] = {
    // Uninitialised
    { { .symbol = "1", .text = "  Setup Jade", .btn_id = BTN_INITIALIZE },
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        { .symbol = "2", .text = " Scan SeedQR", .btn_id = BTN_SCAN_SEEDQR },
#endif
        { .symbol = "3", .text = "    Options", .btn_id = BTN_SETTINGS } },

    // Initialised/Locked
    { { .symbol = "5", .text = " Unlock Jade", .btn_id = BTN_CONNECT },
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        { .symbol = "2", .text = "   QR Mode", .btn_id = BTN_QR_MODE },
#endif
        { .symbol = "3", .text = "    Options", .btn_id = BTN_SETTINGS } },

    // Active/Unlocked/Ready
    { { .symbol = "4", .text = "    Session", .btn_id = BTN_SESSION },
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        { .symbol = "2", .text = "   Scan QR", .btn_id = BTN_SCAN_QR },
#endif
        { .symbol = "3", .text = "    Options", .btn_id = BTN_SETTINGS } }
};

// The device name and running firmware info, loaded at startup
static const char* device_name;
static esp_app_desc_t running_app_info;

// Functional actions
void register_otp_process(void* process_ptr);
void get_otp_code_process(void* process_ptr);
void get_xpubs_process(void* process_ptr);
void get_registered_multisigs_process(void* process_ptr);
void register_multisig_process(void* process_ptr);
void get_receive_address_process(void* process_ptr);
void get_identity_pubkey_process(void* process_ptr);
void get_identity_shared_key_process(void* process_ptr);
void sign_identity_process(void* process_ptr);
void sign_message_process(void* process_ptr);
void sign_psbt_process(void* process_ptr);
void sign_tx_process(void* process_ptr);
void get_master_blinding_key_process(void* process_ptr);
void get_blinding_key_process(void* process_ptr);
void get_shared_nonce_process(void* process_ptr);
void get_commitments_process(void* process_ptr);
void get_blinding_factor_process(void* process_ptr);
void sign_liquid_tx_process(void* process_ptr);
#ifdef CONFIG_DEBUG_MODE
void debug_capture_image_data_process(void* process_ptr);
void debug_scan_qr_process(void* process_ptr);
void debug_set_mnemonic_process(void* process_ptr);
void debug_clean_reset_process(void* process_ptr);
void debug_handshake(void* process_ptr);
bool debug_selfcheck(jade_process_t* process);
#endif
void ota_process(void* process_ptr);
void ota_delta_process(void* process_ptr);
void update_pinserver_process(void* process_ptr);
void auth_user_process(void* process_ptr);

// Home screen
gui_activity_t* make_home_screen_activity(const char* device_name, const char* firmware_version,
    gui_view_node_t** item_symbol, gui_view_node_t** item_text, gui_view_node_t** status_light,
    gui_view_node_t** status_text, gui_view_node_t** label);

// Temporary screens while connecting
gui_activity_t* make_connect_activity(const char* device_name);
gui_activity_t* make_connect_to_activity(const char* device_name, jade_msg_source_t initialisation_source);

// GUI screens
gui_activity_t* make_select_connection_activity_if_required(bool temporary_restore);
gui_activity_t* make_connect_qrmode_activity(const char* device_name);

gui_activity_t* make_startup_options_activity(void);
gui_activity_t* make_uninitialised_settings_activity(void);
gui_activity_t* make_locked_settings_activity(void);
gui_activity_t* make_unlocked_settings_activity(void);

gui_activity_t* make_wallet_settings_activity(void);
gui_activity_t* make_device_settings_activity(void);
gui_activity_t* make_authentication_activity(void);
gui_activity_t* make_prefs_settings_activity(bool show_ble);

gui_activity_t* make_info_activity(const char* fw_version);
gui_activity_t* make_device_info_activity(void);

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
gui_activity_t* make_legal_certifications_activity(void);
#endif
gui_activity_t* make_storage_stats_activity(size_t entries_used, size_t entries_free);

gui_activity_t* make_wallet_erase_pin_info_activity(void);
gui_activity_t* make_wallet_erase_pin_options_activity(gui_view_node_t** pin_text);

gui_activity_t* make_bip39_passphrase_prefs_activity(
    gui_view_node_t** frequency_textbox, gui_view_node_t** method_textbox);

gui_activity_t* make_otp_activity(void);
gui_activity_t* make_new_otp_activity(void);

bool show_otp_details_activity(
    const otpauth_ctx_t* ctx, bool initial_confirmation, bool is_valid, bool show_delete_btn);
gui_activity_t* make_show_hotp_code_activity(const char* name, const char* codestr, bool confirm_only);
gui_activity_t* make_show_totp_code_activity(const char* name, const char* timestamp, const char* codestr,
    bool confirm_only, progress_bar_t* progress_bar, gui_view_node_t** txt_ts, gui_view_node_t** txt_code);

gui_activity_t* make_pinserver_activity(void);

bool show_view_multisig_activity(const char* multisig_name, bool initial_confirmation, bool is_valid, bool is_sorted,
    size_t threshold, size_t num_signers, const char* master_blinding_key_hex);

gui_activity_t* make_session_activity(void);
gui_activity_t* make_ble_activity(gui_view_node_t** ble_status_item);

// Wallet initialisation function
void initialise_with_mnemonic(bool temporary_restore, bool force_qr_scan);

// Register a new otp code
bool register_otp_qr(void);
bool register_otp_kb_entry(void);

// Updating Pinserver settings
void show_pinserver_details(void);
bool handle_update_pinserver_qr(const uint8_t* cbor, const size_t cbor_len);
bool reset_pinserver(void);

// Bip85
void handle_bip85_mnemonic();

// Home screen/menu update
static void update_home_screen(gui_view_node_t* status_light, gui_view_node_t* status_text, gui_view_node_t* label)
{
    JADE_ASSERT(status_light);
    JADE_ASSERT(status_text);
    JADE_ASSERT(label);

    if (home_screen_type == HOME_SCREEN_TYPE_ACTIVE) {
        gui_set_color(status_light, TFT_BLOCKSTREAM_DARKGREEN);
        gui_update_text(status_light, keychain_has_temporary() ? "N" : "J"); // Clock or Filled circle
        gui_update_text(status_text, "Active");

        // Wallet fingerprint in uppercase hex
        char* fphex = NULL;
        uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        wallet_get_fingerprint(fingerprint, sizeof(fingerprint));
        JADE_WALLY_VERIFY(wally_hex_from_bytes(fingerprint, sizeof(fingerprint), &fphex));
        map_string(fphex, toupper);
        gui_update_text(label, fphex);
        JADE_WALLY_VERIFY(wally_free_string(fphex));
    } else if (home_screen_type == HOME_SCREEN_TYPE_LOCKED) {
        gui_set_color(status_light, TFT_LIGHTGREY);
        gui_update_text(status_light, "J"); // Filled circle
        gui_update_text(status_text, "Initialized");
        gui_update_text(label, running_app_info.version);
    } else if (home_screen_type == HOME_SCREEN_TYPE_UNINIT) {
        gui_set_color(status_light, TFT_BLOCKSTREAM_BUTTONBORDER_GREY);
        gui_update_text(status_light, "J"); // Filled circle
        gui_update_text(status_text, "Uninitialized");
        gui_update_text(label, running_app_info.version);
    } else {
        JADE_ASSERT_MSG(false, "Unexpected home screen type: %u", home_screen_type);
    }
}

static const home_menu_item_t* get_selected_home_screen_menu_item(void)
{
    JADE_ASSERT(home_screen_type < sizeof(home_menu_items) / sizeof(home_menu_items[0]));
    JADE_ASSERT(home_screen_menu_item < sizeof(home_menu_items[0]) / sizeof(home_menu_items[0][0]));
    const home_menu_item_t* const menu_item = &home_menu_items[home_screen_type][home_screen_menu_item];
    return menu_item;
}

static void update_home_screen_menu(void)
{
    JADE_ASSERT(home_screen_item_symbol);
    JADE_ASSERT(home_screen_item_text);

    const home_menu_item_t* const menu_item = get_selected_home_screen_menu_item();
    JADE_ASSERT(menu_item->text);
    JADE_ASSERT(menu_item->symbol);

    gui_update_text(home_screen_item_symbol, menu_item->symbol);
    gui_update_text(home_screen_item_text, menu_item->text);
}

// Function to print a pin into a char buffer.
// Assumes each pin component value is a single digit.
// NOTE: the passed buffer must be large enough.
// (In normal circumstances that should be PIN_SIZE digits)
static void format_pin(char* buf, const uint8_t buf_len, const uint8_t* pin, const size_t pin_len)
{
    JADE_ASSERT(pin_len == PIN_SIZE);
    JADE_ASSERT(buf_len > pin_len);

    for (int i = 0; i < pin_len; ++i) {
        JADE_ASSERT(pin[i] < 10);
        const int ret = snprintf(buf++, buf_len - i, "%d", pin[i]);
        JADE_ASSERT(ret == 1);
    }
}

static void reply_version_info(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(container);

    const jade_process_t* process = (const jade_process_t*)ctx;

#ifdef CONFIG_DEBUG_MODE
    const uint8_t num_version_fields = 19;
#else
    const uint8_t num_version_fields = 12;
#endif

    CborEncoder map_encoder;
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, num_version_fields);
    JADE_ASSERT(cberr == CborNoError);

    add_string_to_map(&map_encoder, "JADE_VERSION", running_app_info.version);
    add_uint_to_map(&map_encoder, "JADE_OTA_MAX_CHUNK", JADE_OTA_BUF_SIZE);

    // Config - eg. ble/radio enabled in build, or not
    // defined in ota.h
    add_string_to_map(&map_encoder, "JADE_CONFIG", JADE_OTA_CONFIG);

    // Board type - Production Jade, M5Stack, esp32 dev board, etc.
    // defined in ota.h
    add_string_to_map(&map_encoder, "BOARD_TYPE", JADE_OTA_BOARD_TYPE);

    // hardware 'features' eg. 'secure boot' or 'dev' etc.
    // defined in ota.h
    add_string_to_map(&map_encoder, "JADE_FEATURES", JADE_OTA_FEATURES);

    const char* idfversion = esp_get_idf_version();
    add_string_to_map(&map_encoder, "IDF_VERSION", idfversion);

    esp_chip_info_t info;
    esp_chip_info(&info);

    char* hexstr = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes((uint8_t*)&info.features, 4, &hexstr));
    add_string_to_map(&map_encoder, "CHIP_FEATURES", hexstr);
    JADE_WALLY_VERIFY(wally_free_string(hexstr));

    uint8_t macid[6];
    esp_efuse_mac_get_default(macid);
    JADE_WALLY_VERIFY(wally_hex_from_bytes(macid, 6, &hexstr));
    map_string(hexstr, toupper);
    add_string_to_map(&map_encoder, "EFUSEMAC", hexstr);
    JADE_WALLY_VERIFY(wally_free_string(hexstr));

    // Battery level
    add_uint_to_map(&map_encoder, "BATTERY_STATUS", power_get_battery_status());

    // We have five cases:
    // 1. Ready - has keys already associated with a message source
    //    - READY
    // 2. Temporary keys - has temporary keys in memory, but not yet connected to app
    //    - TEMP
    // 3. Unsaved keys - has proper keys in memory, but not yet saved with a PIN
    //    - UNSAVED
    // 4. Locked - has persisted/encrypted keys, but no keys in memory
    //    - LOCKED
    // 5. Uninitialised - has no persisted/encrypted keys and no keys in memory
    //    - UNINIT

    const bool has_pin = keychain_has_pin();
    const bool has_keys = keychain_get() != NULL;
    if (has_keys) {
        if (KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)) {
            add_string_to_map(&map_encoder, "JADE_STATE", "READY");
        } else if (keychain_get_userdata() != SOURCE_NONE) {
            // Other connection interface in use - so this interface is 'locked'
            add_string_to_map(&map_encoder, "JADE_STATE", "LOCKED");
        } else if (keychain_has_temporary()) {
            add_string_to_map(&map_encoder, "JADE_STATE", "TEMP");
        } else {
            add_string_to_map(&map_encoder, "JADE_STATE", "UNSAVED");
        }
    } else {
        add_string_to_map(&map_encoder, "JADE_STATE", has_pin ? "LOCKED" : "UNINIT");
    }

    const network_type_t restriction = keychain_get_network_type_restriction();
    const char* networks = restriction == NETWORK_TYPE_MAIN ? "MAIN"
        : restriction == NETWORK_TYPE_TEST                  ? "TEST"
                                                            : "ALL";
    add_string_to_map(&map_encoder, "JADE_NETWORKS", networks);

    // Deprecated (as of 0.1.25) - to be removed later
    add_boolean_to_map(&map_encoder, "JADE_HAS_PIN", has_pin);

// Memory stats only needed in DEBUG
#ifdef CONFIG_DEBUG_MODE
    size_t entries_used, entries_free;
    const bool ok = storage_get_stats(&entries_used, &entries_free);
    add_uint_to_map(&map_encoder, "JADE_NVS_ENTRIES_USED", ok ? entries_used : 0);
    add_uint_to_map(&map_encoder, "JADE_NVS_ENTRIES_FREE", ok ? entries_free : 0);

    add_uint_to_map(&map_encoder, "JADE_FREE_HEAP", xPortGetFreeHeapSize());
    add_uint_to_map(&map_encoder, "JADE_FREE_DRAM", heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));
    add_uint_to_map(
        &map_encoder, "JADE_LARGEST_DRAM", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));
    add_uint_to_map(&map_encoder, "JADE_FREE_SPIRAM", heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM));
    add_uint_to_map(
        &map_encoder, "JADE_LARGEST_SPIRAM", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM));
#endif // CONFIG_DEBUG_MODE

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

// Unpack entropy bytes from message and add to random generator
static void process_add_entropy_request(jade_process_t* process)
{
    const uint8_t* entropy = NULL;
    size_t written = 0;

    ASSERT_CURRENT_MESSAGE(process, "add_entropy");
    GET_MSG_PARAMS(process);

    rpc_get_bytes_ptr("entropy", &params, &entropy, &written);

    if (!written) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid entropy bytes from parameters", NULL);
        goto cleanup;
    }

    // Feed received entropy into the random gnerator
    refeed_entropy(entropy, written);
    jade_process_reply_to_message_ok(process);

cleanup:
    return;
}

// Set the current time epoch value
static void process_set_epoch_request(jade_process_t* process)
{
    ASSERT_CURRENT_MESSAGE(process, "set_epoch");
    GET_MSG_PARAMS(process);

    const char* errmsg = NULL;
    const int errcode = params_set_epoch_time(&params, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    jade_process_reply_to_message_ok(process);

cleanup:
    return;
}

// Logout of jade hww, clear all key material
static void process_logout_request(jade_process_t* process)
{
    ASSERT_CURRENT_MESSAGE(process, "logout");
    keychain_clear();
    jade_process_reply_to_message_ok(process);
}

// method_name should be a string literal - or at least non-null and nul terminated
#define IS_METHOD(method_name) (!strncmp(method, method_name, method_len) && strlen(method_name) == method_len)

// Message dispatcher - expects valid cbor messages, routed by 'method'
static void dispatch_message(jade_process_t* process)
{
    ASSERT_HAS_CURRENT_MESSAGE(process);
    JADE_ASSERT(process->ctx.cbor);
    JADE_ASSERT(process->ctx.cbor_len);

    size_t method_len = 0;
    const char* method = NULL;
    rpc_get_method(&process->ctx.value, &method, &method_len);
    JADE_ASSERT(method_len != 0);

    TaskFunction_t task_function = NULL;

    JADE_LOGD("dashboard dispatching message method='%.*s'", method_len, method);

    // Methods available before user is authorised
    if (IS_METHOD("get_version_info")) {
        JADE_LOGD("Received request for version");
        jade_process_reply_to_message_result(process->ctx, process, reply_version_info);
    } else if (IS_METHOD("add_entropy")) {
        JADE_LOGD("Received external entropy message");
        process_add_entropy_request(process);
    } else if (IS_METHOD("set_epoch")) {
        JADE_LOGD("Received set-epoch message");
        process_set_epoch_request(process);
    } else if (IS_METHOD("logout")) {
        JADE_LOGD("Received logout message");
        process_logout_request(process);
    } else if (IS_METHOD("update_pinserver")) {
        JADE_LOGD("Received update to pinserver details");
        task_function = update_pinserver_process;
    } else if (IS_METHOD("auth_user")) {
        JADE_LOGD("Received auth-user request");
        task_function = auth_user_process;
    } else if (IS_METHOD("cancel")) {
        // 'cancel' is completely ignored (as nothing is 'in-progress' to cancel)
        JADE_LOGD("Received 'cancel' request - no-op");
    } else if (IS_METHOD("ota")) {
        // OTA is allowed if either:
        // a) User has passed PIN screen and has unlocked Jade saved wallet
        // or
        // b) There is no PIN set (ie. no encrypted keys set, eg. new device)
        if ((KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process) && !keychain_has_temporary()) || !keychain_has_pin()) {
            task_function = ota_process;
        } else {
            // Reject the message as hw locked
            jade_process_reject_message(
                process, CBOR_RPC_HW_LOCKED, "OTA is only allowed on new or logged-in device.", NULL);
        }
    } else if (IS_METHOD("ota_delta")) {
        // OTA delta is allowed if either:
        // a) User has passed PIN screen and has unlocked Jade saved wallet
        // or
        // b) There is no PIN set (ie. no encrypted keys set, eg. new device)
        if ((KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process) && !keychain_has_temporary()) || !keychain_has_pin()) {
            task_function = ota_delta_process;
        } else {
            // Reject the message as hw locked
            jade_process_reject_message(
                process, CBOR_RPC_HW_LOCKED, "OTA delta is only allowed on new or logged-in device.", NULL);
        }
#ifdef CONFIG_DEBUG_MODE
    } else if (IS_METHOD("debug_selfcheck")) {
        // Time test run and return to caller
        const TickType_t start_time = xTaskGetTickCount();
        if (debug_selfcheck(process)) {
            const TickType_t end_time = xTaskGetTickCount();
            const uint64_t elapsed_time_ms = (end_time - start_time) * portTICK_PERIOD_MS;
            jade_process_reply_to_message_result(process->ctx, &elapsed_time_ms, cbor_result_uint64_cb);
        } else {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "ERROR", NULL);
        }
    } else if (IS_METHOD("debug_clean_reset")) {
        task_function = debug_clean_reset_process;
    } else if (IS_METHOD("debug_set_mnemonic")) {
        task_function = debug_set_mnemonic_process;
    } else if (IS_METHOD("debug_handshake")) {
        task_function = debug_handshake;
    } else if (IS_METHOD("debug_scan_qr")) {
        task_function = debug_scan_qr_process;
#ifdef CONFIG_RETURN_CAMERA_IMAGES
    } else if (IS_METHOD("debug_capture_image_data")) {
        task_function = debug_capture_image_data_process;
#endif // CONFIG_RETURN_CAMERA_IMAGES
#endif // CONFIG_DEBUG_MODE
    } else {
        // Methods only available after user authorised
        if (!KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)) {
            // Reject the message as hw locked
            jade_process_reject_message(
                process, CBOR_RPC_HW_LOCKED, "Cannot process message - hardware locked or uninitialized", NULL);
        } else if (IS_METHOD("register_otp")) {
            task_function = register_otp_process;
        } else if (IS_METHOD("get_otp_code")) {
            task_function = get_otp_code_process;
        } else if (IS_METHOD("get_xpub")) {
            task_function = get_xpubs_process;
        } else if (IS_METHOD("get_registered_multisigs")) {
            task_function = get_registered_multisigs_process;
        } else if (IS_METHOD("register_multisig")) {
            task_function = register_multisig_process;
        } else if (IS_METHOD("get_receive_address")) {
            task_function = get_receive_address_process;
        } else if (IS_METHOD("get_identity_pubkey")) {
            task_function = get_identity_pubkey_process;
        } else if (IS_METHOD("get_identity_shared_key")) {
            task_function = get_identity_shared_key_process;
        } else if (IS_METHOD("sign_identity")) {
            task_function = sign_identity_process;
        } else if (IS_METHOD("sign_message")) {
            task_function = sign_message_process;
        } else if (IS_METHOD("sign_psbt")) {
            task_function = sign_psbt_process;
        } else if (IS_METHOD("sign_tx")) {
            task_function = sign_tx_process;
        } else if (IS_METHOD("sign_liquid_tx")) {
            task_function = sign_liquid_tx_process;
        } else if (IS_METHOD("get_commitments")) {
            task_function = get_commitments_process;
        } else if (IS_METHOD("get_blinding_factor")) {
            task_function = get_blinding_factor_process;
        } else if (IS_METHOD("get_master_blinding_key")) {
            task_function = get_master_blinding_key_process;
        } else if (IS_METHOD("get_blinding_key")) {
            task_function = get_blinding_key_process;
        } else if (IS_METHOD("get_shared_nonce")) {
            task_function = get_shared_nonce_process;
        } else if (IS_METHOD("ota_data") || IS_METHOD("ota_complete") || IS_METHOD("tx_input")
            || IS_METHOD("get_extended_data") || IS_METHOD("get_signature") || IS_METHOD("handshake_init")
            || IS_METHOD("handshake_complete")) {
            // Method we only expect as part of a multi-message protocol
            jade_process_reject_message(process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected method", NULL);
        } else {
            // Reject the message as unknown, and free message
            jade_process_reject_message(process, CBOR_RPC_UNKNOWN_METHOD, "Unknown method", NULL);
        }
    }

    if (task_function) {
        // Make new process object for the message
        jade_process_t task_process;
        init_jade_process(&task_process);
        jade_process_transfer_current_message(process, &task_process);

        // re-randomize secp256k1 ctx for this task
        jade_wally_randomize_secp_ctx();

        // Call the function
        task_function(&task_process);

        // Then clean up after the process has finished
        cleanup_jade_process(&task_process);

        // When the authentication process exits, wipe the cached 'initialistion source'
        if (task_function == auth_user_process) {
            initialisation_source = SOURCE_NONE;
            show_connect_screen = false;
        }
    }
}

// Function to get user confirmation, then erase all flash memory.
static void offer_jade_reset(void)
{
    // Run 'Reset Jade?'  confirmation screen and wait for yes/no response
    if (!await_yesno_activity("Factory Reset",
            "Reset Jade and erase all\n  PIN and wallet data?\nThis cannot be undone!", false, "blkstrm.com/reset")) {
        // User decided against it
        return;
    }

    // Force user to confirm a random number
    uint8_t num[PIN_SIZE];
    for (int i = 0; i < PIN_SIZE; ++i) {
        num[i] = get_uniform_random_byte(10);
    }
    char pinstr[sizeof(num) + 1];
    format_pin(pinstr, sizeof(pinstr), num, sizeof(num));

    JADE_LOGI("User must enter: %s to reset all data", pinstr);

    char confirm_msg[64];
    const int ret = snprintf(confirm_msg, sizeof(confirm_msg), "Confirm reset: %s", pinstr);
    JADE_ASSERT(ret > 0 && ret < sizeof(confirm_msg));

    pin_insert_t pin_insert = {};
    make_pin_insert_activity(&pin_insert, "Reset Jade", confirm_msg);
    JADE_ASSERT(pin_insert.activity);
    JADE_ASSERT(sizeof(num) == sizeof(pin_insert.pin));

    gui_set_current_activity(pin_insert.activity);
    run_pin_entry_loop(&pin_insert);

    format_pin(pinstr, sizeof(pinstr), pin_insert.pin, sizeof(pin_insert.pin));
    JADE_LOGI("User entered: %s", pinstr);

    if (!sodium_memcmp(num, pin_insert.pin, sizeof(num))) {
        // Correct - erase all jade non-volatile storage
        JADE_LOGI("User confirmed - erasing Jade data");
        if (storage_erase()) {
            // Erase succeeded, better reboot to re-initialise
            esp_restart();
        } else {
            // Erase failed ?    What can we do other than alert the user ?
            JADE_LOGE("Factory reset failed!");
            await_error_activity("\n\n  Unable to completely\n          reset Jade.");
        }
    } else {
        // Incorrect - continue to boot screen
        JADE_LOGI("User confirmation number incorrect, not wiping data.");
        await_error_activity("\n\n Confirmation number\n          incorrect!");
    }
}

// Offer to communicate with pinserver via QRs
static bool offer_pinserver_via_qr(const bool temporary_restore)
{
    // User to confirm pinserver-via-QR
    if (!temporary_restore) {
        char msg[64];
        const int ret
            = snprintf(msg, sizeof(msg), "      Visit\nblkstrm.com/pn to %s", keychain_has_pin() ? "unlock" : "secure");
        JADE_ASSERT(ret > 0 && ret < sizeof(msg));
        if (!await_qr_back_continue_activity(msg, "blkstrm.com/pn", true)) {
            // User decided against it
            return false;
        }
    }

    // Start pinserver/qr handshake process
    initialisation_source = SOURCE_QR;
    show_connect_screen = true;
    handle_qr_auth();
    return true;
}

// Unlock jade using qr-codes to effect communication with the pinserver
static bool offer_pinserver_qr_unlock()
{
    JADE_ASSERT(keychain_has_pin());
    const bool temporary_restore = keychain_has_temporary();
    JADE_ASSERT(!temporary_restore);
    return offer_pinserver_via_qr(temporary_restore);
}

// Screen to select whether the initial connection is via USB, BLE or QR
static void select_initial_connection(const bool temporary_restore)
{
    // If there are connection options, the user must choose one
    // Otherwise this call returns null and we default to USB
    gui_activity_t* const act = make_select_connection_activity_if_required(temporary_restore);
    initialisation_source = act ? SOURCE_NONE : SOURCE_SERIAL;
    show_connect_screen = true;

    while (initialisation_source == SOURCE_NONE) {
        gui_set_current_activity(act);

        int32_t ev_id;
        // In a debug unattended ci build, assume 'USB' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_CONNECT_VIA_USB;
#endif

        if (ret) {
            if (ev_id == BTN_CONNECT_VIA_USB) {
                // Set USB/SERIAL source
                initialisation_source = SOURCE_SERIAL;
            } else if (ev_id == BTN_CONNECT_VIA_BLE) {
                // Set BLE source and ensure ble enabled now and by default
                initialisation_source = SOURCE_BLE;
                if (!ble_enabled()) {
                    const uint8_t ble_flags = storage_get_ble_flags() | BLE_ENABLED;
                    storage_set_ble_flags(ble_flags);
                    ble_start();
                }
            } else if (ev_id == BTN_CONNECT_VIA_QR) {
                // Offer pinserver via qr with urls etc
                if (offer_pinserver_via_qr(temporary_restore)) {
                    JADE_ASSERT(initialisation_source == SOURCE_QR);
                }
            }
        }
    }
}

// Helper to initialise with mnemonic, and (if successful) request whether the
// initial conenction will be over USB or BLE.
static void initialise_wallet(const bool temporary_restore)
{
    const bool force_qr_scan = false;
    initialise_with_mnemonic(temporary_restore, force_qr_scan);
    if (keychain_get()) {
        select_initial_connection(temporary_restore);
    }
}

static bool offer_temporary_wallet_login(void)
{
    if (!await_continueback_activity(NULL, "      Do you want to\n temporarily login using\a    a recovery phrase?",
            true, "blkstrm.com/temporary")) {
        // User decided against it
        return false;
    }

    // Initialise 'temporary' wallet
    const bool temporary_restore = true;
    initialise_wallet(temporary_restore);
    return true;
}

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
static void handle_legal(void)
{
    gui_activity_t* const first_activity = make_legal_certifications_activity();
    gui_set_current_activity(first_activity);

    while (sync_await_single_event(GUI_BUTTON_EVENT, BTN_LEGAL_EXIT, NULL, NULL, NULL, 0) != ESP_OK) {
        // Wait until we get this event
    }
}
#endif

#ifdef CONFIG_BT_ENABLED
// Reset BLE pairing data
static void handle_ble_reset(void)
{
    if (!ble_enabled()) {
        await_message_activity("\n      You must enable\n     Bluetooth to reset\n            pairings.");
        return;
    }

    if (!await_yesno_activity(
            device_name, "     Delete Bluetooth\n       pairings for all \n      bonded devices?", false, NULL)) {
        return;
    }

    if (ble_remove_all_devices()) {
        await_message_activity("\n\n    Bluetooth pairings\n            deleted");
    } else {
        await_error_activity("\n\n   Failed to remove all\n    Bluetooth pairings!");
    }
}

// BLE properties screen
static void handle_ble(void)
{
    uint8_t ble_flags = storage_get_ble_flags();

    gui_view_node_t* ble_status_item = NULL;
    gui_activity_t* const act = make_ble_activity(&ble_status_item);
    gui_update_text(ble_status_item, ble_enabled() ? "Status: Enabled" : "Status: Disabled");
    gui_set_current_activity(act);

    gui_view_node_t* status_textbox = NULL;
    gui_activity_t* const act_status = make_carousel_activity("Bluetooth Status", NULL, &status_textbox);
    gui_update_text(status_textbox, ble_enabled() ? "Enabled" : "Disabled");

    int32_t ev_id;
    while (true) {
        // Show, and await button click
        gui_set_current_activity(act);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        bool ret = true;
        ev_id = BTN_BLE_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_BLE_STATUS) {
                gui_set_current_activity(act_status);
                bool enable_ble = ble_enabled();
                while (true) {
                    gui_update_text(status_textbox, enable_ble ? "Enabled" : "Disabled");
                    if (gui_activity_wait_event(act_status, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT || ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            enable_ble = !enable_ble; // Just toggle label at this point
                        } else if (ev_id == gui_get_click_event()) {
                            // Done - apply ble change
                            break;
                        }
                    }
                }

                // Start/stop BLE and persist pref/flags
                if (enable_ble) {
                    if (!ble_enabled()) {
                        ble_start();
                    }
                    ble_flags |= BLE_ENABLED;
                    storage_set_ble_flags(ble_flags);
                } else {
                    if (ble_enabled()) {
                        ble_stop();
                    }
                    ble_flags &= ~BLE_ENABLED;
                    storage_set_ble_flags(ble_flags);
                }
                gui_update_text(ble_status_item, ble_enabled() ? "Status: Enabled" : "Status: Disabled");
            } else if (ev_id == BTN_BLE_RESET_PAIRING) {
                handle_ble_reset();
            } else if (ev_id == BTN_BLE_HELP) {
                await_qr_help_activity("blkstrm.com/bluetooth");
            } else if (ev_id == BTN_BLE_EXIT) {
                // Done
                break;
            }
        }
    }
}
#else
static void handle_ble(void) { await_message_activity("\n\n       BLE disabled in\n        this firmware"); }
#endif // CONFIG_BT_ENABLED

// Helper to delete a multisig record after user confirms
static bool delete_multisig_record(const char* multisig_name)
{
    JADE_ASSERT(multisig_name);

    if (!await_yesno_activity("Delete Wallet", multisig_name, false, "blkstrm.com/wallets")) {
        return false;
    }

    if (!storage_erase_multisig_registration(multisig_name)) {
        await_error_activity("\n\n      Failed to delete\n  registered wallet!");
        return false;
    }

    await_message_activity("\n\n    Registered Wallet\n            Deleted");
    return true;
}

static void handle_multisigs(void)
{
    char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_multisigs = 0;
    bool ok = storage_get_all_multisig_registration_names(names, num_names, &num_multisigs);
    JADE_ASSERT(ok);

    if (num_multisigs == 0) {
        await_message_activity("\n\n   No additional wallets\n          registered");
        return;
    }

    size_t selected = 0;
    gui_view_node_t* walletname = NULL;
    gui_activity_t* const act = make_carousel_activity("View Wallet", NULL, &walletname);
    gui_update_text(walletname, names[selected]);
    gui_set_current_activity(act);
    int32_t ev_id;

    bool done = false;
    while (!done) {
        JADE_ASSERT(selected < num_multisigs);
        gui_update_text(walletname, names[selected]);

        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            switch (ev_id) {
            case GUI_WHEEL_LEFT_EVENT:
                selected = (selected + num_multisigs - 1) % num_multisigs;
                break;

            case GUI_WHEEL_RIGHT_EVENT:
                selected = (selected + 1) % num_multisigs;
                break;

            default:
                if (ev_id == gui_get_click_event()) {
                    done = true;
                    break;
                }
            }
        }
    }

    // Load selected multisig record from storage given the name
    JADE_ASSERT(selected < num_multisigs);
    const char* errmsg = NULL;
    multisig_data_t multisig_data;
    const bool is_valid = multisig_load_from_storage(names[selected], &multisig_data, &errmsg);
    const bool initial_confirmation = false;

    // We will display the names of invalid entries, just log any message
    if (errmsg) {
        JADE_LOGW("%s", errmsg);
    }

    char* master_blinding_key_hex = NULL;
    if (is_valid && multisig_data.master_blinding_key_len) {
        JADE_WALLY_VERIFY(wally_hex_from_bytes(
            multisig_data.master_blinding_key, multisig_data.master_blinding_key_len, &master_blinding_key_hex));
    }
    if (!show_view_multisig_activity(names[selected], initial_confirmation, is_valid, multisig_data.sorted,
            multisig_data.threshold, multisig_data.num_xpubs, master_blinding_key_hex)) {
        // Delete record
        delete_multisig_record(names[selected]);
    }
    if (master_blinding_key_hex) {
        JADE_WALLY_VERIFY(wally_free_string(master_blinding_key_hex));
    }
}

static void set_wallet_erase_pin(void)
{
    JADE_LOGI("Requesting wallet-erase PIN");

    // Ask user to enter a wallet-erase pin
    pin_insert_t pin_insert = {};
    make_pin_insert_activity(&pin_insert, "Wallet-Erase PIN", "Different from main PIN");
    JADE_ASSERT(pin_insert.activity);

    while (true) {
        gui_set_current_activity(pin_insert.activity);

        run_pin_entry_loop(&pin_insert);

        // This is the first pin, copy it and clear screen fields
        uint8_t pin[sizeof(pin_insert.pin)];
        memcpy(pin, pin_insert.pin, sizeof(pin));
        reset_pin(&pin_insert, "Confirm Erase PIN");

        // Ask user to re-enter PIN
        run_pin_entry_loop(&pin_insert);

        // Check that the two pins are the same
        JADE_LOGD("Checking pins match");
        if (!sodium_memcmp(pin, pin_insert.pin, sizeof(pin))) {
            JADE_LOGI("Setting Wallet-Erase PIN");
            storage_set_wallet_erase_pin(pin_insert.pin, sizeof(pin_insert.pin));
            break;
        } else {
            // Pins mismatch - try again
            if (!await_continueback_activity(NULL, "        Pin mismatch,\n      please try again.", true, NULL)) {
                // Abandon
                break;
            }
            reset_pin(&pin_insert, "Wallet-Erase PIN");
        }
    }
}

static void handle_wallet_erase_pin(void)
{
    gui_activity_t* act_info = make_wallet_erase_pin_info_activity();

    gui_view_node_t* pin_text = NULL;
    gui_activity_t* act_options = make_wallet_erase_pin_options_activity(&pin_text);
    JADE_ASSERT(pin_text);

    while (true) {
        // Add wallet erase pin confirmation screens
        uint8_t pin_erase[PIN_SIZE];
        gui_activity_t* act = NULL;
        if (storage_get_wallet_erase_pin(pin_erase, sizeof(pin_erase))) {
            char pinstr[sizeof(pin_erase) + 1];
            format_pin(pinstr, sizeof(pinstr), pin_erase, sizeof(pin_erase));
            gui_update_text(pin_text, pinstr);
            act = act_options;
        } else {
            act = act_info;
        }
        gui_set_current_activity(act);

        int32_t ev_id;
        if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == BTN_WALLET_ERASE_PIN_SET) {
                // User opted to set a new wallet-erasing PIN
                set_wallet_erase_pin();
            } else if (ev_id == BTN_WALLET_ERASE_PIN_DISABLE) {
                // User opted to disable/erase wallet-erasing PIN
                JADE_LOGI("Erasing Wallet-Erase PIN");
                storage_erase_wallet_erase_pin();
                await_message_activity("\n\n      Wallet-Erase PIN\n            deleted");
            } else if (ev_id == BTN_WALLET_ERASE_PIN_HELP) {
                await_qr_help_activity("blkstrm.com/duress");
            } else if (ev_id == BTN_WALLET_ERASE_PIN_EXIT) {
                // Done
                break;
            }
        }
    }
}

// Handle passphrase preferences
static inline const char* passphrase_frequency_desc_from_flags(const passphrase_freq_t freq)
{
    return freq == PASSPHRASE_ALWAYS ? "Always" : freq == PASSPHRASE_ONCE ? "Once" : "Never";
}
static inline const char* passphrase_method_desc_from_flags(const passphrase_type_t type)
{
    return type == PASSPHRASE_WORDLIST ? "WordList" : "Manual";
}

static void handle_passphrase_prefs()
{
    passphrase_freq_t freq = keychain_get_passphrase_freq();
    passphrase_type_t type = keychain_get_passphrase_type();

    gui_view_node_t* frequency_item = NULL;
    gui_view_node_t* method_item = NULL;
    gui_activity_t* const act = make_bip39_passphrase_prefs_activity(&frequency_item, &method_item);
    update_menu_item(frequency_item, "Frequency", passphrase_frequency_desc_from_flags(freq));
    update_menu_item(method_item, "Method", passphrase_method_desc_from_flags(type));
    gui_set_current_activity(act);

    gui_view_node_t* frequency_textbox = NULL;
    gui_activity_t* const act_freq = make_carousel_activity("Frequency", NULL, &frequency_textbox);
    gui_update_text(frequency_textbox, passphrase_frequency_desc_from_flags(freq));

    gui_view_node_t* method_textbox = NULL;
    gui_activity_t* const act_method = make_carousel_activity("Method", NULL, &method_textbox);
    gui_update_text(method_textbox, passphrase_method_desc_from_flags(type));

    int32_t ev_id;
    while (true) {
        // Show, and await button click
        gui_set_current_activity(act);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        bool ret = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        bool ret = true;
        ev_id = BTN_PASSPHRASE_EXIT;
#endif
        if (ret) {
            if (ev_id == BTN_PASSPHRASE_FREQUENCY) {
                // Never -> Once -> Always -> Once ...
                gui_set_current_activity(act_freq);
                while (true) {
                    gui_update_text(frequency_textbox, passphrase_frequency_desc_from_flags(freq));
                    if (gui_activity_wait_event(act_freq, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                            freq = (freq == PASSPHRASE_NEVER  ? PASSPHRASE_ALWAYS
                                    : freq == PASSPHRASE_ONCE ? PASSPHRASE_NEVER
                                                              : PASSPHRASE_ONCE);
                        } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            freq = (freq == PASSPHRASE_NEVER  ? PASSPHRASE_ONCE
                                    : freq == PASSPHRASE_ONCE ? PASSPHRASE_ALWAYS
                                                              : PASSPHRASE_NEVER);
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(frequency_item, "Frequency", passphrase_frequency_desc_from_flags(freq));
            } else if (ev_id == BTN_PASSPHRASE_METHOD) {
                gui_set_current_activity(act_method);
                while (true) {
                    gui_update_text(method_textbox, passphrase_method_desc_from_flags(type));
                    if (gui_activity_wait_event(act_method, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                        if (ev_id == GUI_WHEEL_LEFT_EVENT || ev_id == GUI_WHEEL_RIGHT_EVENT) {
                            type = (type == PASSPHRASE_FREETEXT ? PASSPHRASE_WORDLIST : PASSPHRASE_FREETEXT);
                        } else if (ev_id == gui_get_click_event()) {
                            // Done
                            break;
                        }
                    }
                }
                update_menu_item(method_item, "Method", passphrase_method_desc_from_flags(type));
            } else if (ev_id == BTN_PASSPHRASE_HELP) {
                await_qr_help_activity("blkstrm.com/passphrase");
            } else if (ev_id == BTN_PASSPHRASE_EXIT) {
                // Done
                break;
            }
        }
    }

    // If user updated the passphrase settings, save the new settings
    if (freq != keychain_get_passphrase_freq() || type != keychain_get_passphrase_type()) {
        keychain_set_passphrase_frequency(freq);
        keychain_set_passphrase_type(type);
        keychain_persist_passphrase_prefs();
    }
}

// Helper to delete an otp record after user confirms
static bool delete_otp_record(const char* otpname)
{
    JADE_ASSERT(otpname);

    if (!await_yesno_activity("Delete OTP Record", otpname, false, "blkstrm.com/otp")) {
        return false;
    }

    if (!storage_erase_otp(otpname)) {
        await_error_activity("\n\n      Failed to delete\n         OTP record!");
        return false;
    }

    await_message_activity("OTP Record Deleted");
    return true;
}

// HOTP token-code fixed
static bool display_hotp_screen(const otpauth_ctx_t* otp_ctx, const char* token, const bool confirm_only)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(token);

    gui_activity_t* const act = make_show_hotp_code_activity(otp_ctx->name, token, confirm_only);
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
        ev_id = BTN_OTP_RETAIN_CONFIRM;
#endif

        if (ret) {
            if (ev_id == BTN_OTP_DETAILS) {
                const bool is_valid = true; // asserted above
                const bool initial_confirmation = false;
                const bool show_delete_btn = false;
                const bool retain = show_otp_details_activity(otp_ctx, initial_confirmation, is_valid, show_delete_btn);
                JADE_ASSERT(retain); // should be no 'discard' option
            } else if (ev_id == BTN_OTP_DISCARD_DELETE) {
                if (confirm_only || delete_otp_record(otp_ctx->name))
                    return false;
            } else if (ev_id == BTN_OTP_RETAIN_CONFIRM) {
                return true;
            }
        }
    }
}

// TOTP token-code display updates with passage of time (unless flagged not to)
static bool display_totp_screen(otpauth_ctx_t* otp_ctx, uint64_t epoch_value, char* token, const size_t token_len,
    const bool confirm_only, const bool auto_update)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(otp_ctx->otp_type == OTPTYPE_TOTP);
    JADE_ASSERT(token);

    char timestr[32];
    ctime_r((time_t*)&epoch_value, timestr);

    gui_view_node_t* txt_ts = NULL;
    gui_view_node_t* txt_code = NULL;
    progress_bar_t time_left = {};
    gui_activity_t* const act
        = make_show_totp_code_activity(otp_ctx->name, timestr, token, confirm_only, &time_left, &txt_ts, &txt_code);
    JADE_ASSERT(txt_ts);
    JADE_ASSERT(txt_code);

    gui_set_current_activity(act);
    vTaskDelay(100 / portTICK_PERIOD_MS);

    // Make an event-data structure to track events - attached to the activity
    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(act);
    JADE_ASSERT(event_data);

    // Register for button events
    gui_activity_register_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);
    int32_t ev_id;

    // Token code updates with time (unless explicitly specified otherwise - eg. test fixed value)
    uint8_t count = epoch_value % otp_ctx->period;
    uint8_t last_count = count;
    while (true) {
        gui_set_current_activity(act);

        // Update values
        if (auto_update) {
            if (!otp_set_default_value(otp_ctx, &epoch_value)) {
                await_error_activity("\n\n       Failed to fetch\n        time/counter!");
                return false;
            }
            ctime_r((time_t*)&epoch_value, timestr);
            gui_update_text(txt_ts, timestr);

            count = epoch_value % otp_ctx->period;
            if (count < last_count) {
                // Wrapped - token code should have changed
                if (!otp_get_auth_code(otp_ctx, token, token_len)) {
                    await_error_activity("\n\n    Failed to calculate\n              OTP!");
                    return false;
                }
                gui_update_text(txt_code, token);
            }
            last_count = count;
        }

        // NOTE: this is outside the 'auto-update' check as the
        // progress-bar needs to be updated at least once.
        update_progress_bar(&time_left, otp_ctx->period, count);

        // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        // update every 1s
        const bool ret = sync_wait_event(event_data, NULL, &ev_id, NULL, 1000 / portTICK_PERIOD_MS) == ESP_OK;
#else
        sync_wait_event(event_data, NULL, &ev_id, NULL, CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_OTP_RETAIN_CONFIRM;
#endif

        if (ret) {
            if (ev_id == BTN_OTP_DETAILS) {
                const bool is_valid = true; // asserted above
                const bool initial_confirmation = false;
                const bool show_delete_btn = false;
                const bool retain = show_otp_details_activity(otp_ctx, initial_confirmation, is_valid, show_delete_btn);
                JADE_ASSERT(retain); // should be no 'discard' option
            } else if (ev_id == BTN_OTP_DISCARD_DELETE) {
                if (confirm_only || delete_otp_record(otp_ctx->name))
                    return false;
            } else if (ev_id == BTN_OTP_RETAIN_CONFIRM) {
                return true;
            }
        }
    }
}

bool display_otp_screen(otpauth_ctx_t* otp_ctx, const uint64_t value, char* token, const size_t token_len,
    const bool confirm_only, const bool auto_update)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(token);

    if (otp_ctx->otp_type == OTPTYPE_TOTP) {
        // Token code updates with time (unless explicitly specified otherwise - eg. test fixed value)
        return display_totp_screen(otp_ctx, value, token, token_len, confirm_only, auto_update);
    } else {
        // NOTE: the 'auto_update' flag is ignored as the hotp counter does not change without
        // the caller making an entirely new 'get token code' request - so the value is fixed.
        // Also, ignore counter value as not displayed.
        return display_hotp_screen(otp_ctx, token, confirm_only);
    }
}

static bool show_otp_code(otpauth_ctx_t* otp_ctx)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));

    // Update context with current default 'moving' element
    uint64_t value = 0;
    if (!otp_set_default_value(otp_ctx, &value)) {
        await_error_activity("\n\n       Failed to fetch\n        time/counter!");
        return false;
    }

    // Calculate token
    char token[OTP_MAX_TOKEN_LEN];
    if (!otp_get_auth_code(otp_ctx, token, sizeof(token))) {
        await_error_activity("\n\n    Failed to calculate\n              OTP!");
        return false;
    }

    // totp token/code updates with time
    const bool auto_update = true;
    const bool confirm_only = false;
    display_otp_screen(otp_ctx, value, token, sizeof(token), confirm_only, auto_update);
    return true;
}

static void handle_view_otps(void)
{
    char names[OTP_MAX_RECORDS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_otp_records = 0;
    bool ok = storage_get_all_otp_names(names, num_names, &num_otp_records);
    JADE_ASSERT(ok);

    if (num_otp_records == 0) {
        await_message_activity("\n\n      No OTP records\n          registered");
        return;
    }

    size_t selected = 0;
    gui_view_node_t* otpname = NULL;
    gui_activity_t* const act = make_carousel_activity("View OTP", NULL, &otpname);
    gui_update_text(otpname, names[selected]);
    gui_set_current_activity(act);
    int32_t ev_id;

    bool done = false;
    while (!done) {
        JADE_ASSERT(selected < num_otp_records);
        gui_update_text(otpname, names[selected]);

        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            switch (ev_id) {
            case GUI_WHEEL_LEFT_EVENT:
                selected = (selected + num_otp_records - 1) % num_otp_records;
                break;

            case GUI_WHEEL_RIGHT_EVENT:
                selected = (selected + 1) % num_otp_records;
                break;

            default:
                if (ev_id == gui_get_click_event()) {
                    done = true;
                    break;
                }
            }
        }
    }

    // Load selected OTP record from storage given the name
    JADE_ASSERT(selected < num_otp_records);
    char otp_uri[OTP_MAX_URI_LEN];
    SENSITIVE_PUSH(otp_uri, sizeof(otp_uri));
    otpauth_ctx_t otp_ctx = { .name = names[selected] };

    size_t written = 0;
    const bool is_valid = otp_load_uri(names[selected], otp_uri, sizeof(otp_uri), &written) && written
        && otp_uri_to_ctx(otp_uri, written, &otp_ctx) && otp_is_valid(&otp_ctx);

    // We will display the names of invalid entries and allow the user to delete
    if (!is_valid || !show_otp_code(&otp_ctx)) {
        JADE_LOGE("Error loading or executing otp record: %s", names[selected]);
        const bool initial_confirmation = false;
        const bool show_delete_btn = true;
        if (!show_otp_details_activity(&otp_ctx, initial_confirmation, is_valid, show_delete_btn)) {
            // Delete invalid record
            delete_otp_record(otp_ctx.name);
        }
    }
    SENSITIVE_POP(otp_uri);
}

// NOTE: Only Jade v1.1's have brightness controls
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
static void handle_screen_brightness(void)
{
    static const char* LABELS[] = { "Min(1)", "Low(2)", "Medium(3)", "High(4)", "Max(5)" };

    const uint8_t initial_brightness = storage_get_brightness();
    uint8_t new_brightness = initial_brightness;
    if (new_brightness < BACKLIGHT_MIN) {
        new_brightness = BACKLIGHT_MIN;
    }
    if (new_brightness > BACKLIGHT_MAX) {
        new_brightness = BACKLIGHT_MAX;
    }

    gui_view_node_t* item_text = NULL;
    gui_activity_t* const act = make_carousel_activity("Brightness", NULL, &item_text);
    JADE_ASSERT(item_text);
    gui_update_text(item_text, LABELS[new_brightness - 1]);
    gui_set_current_activity(act);

    int32_t ev_id;
    bool done = false;
    while (!done) {
        // wait for a GUI event
        gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case GUI_WHEEL_LEFT_EVENT:
            if (new_brightness > BACKLIGHT_MIN) {
                power_backlight_on(--new_brightness);
                gui_update_text(item_text, LABELS[new_brightness - 1]);
            }
            break;

        case GUI_WHEEL_RIGHT_EVENT:
            if (new_brightness < BACKLIGHT_MAX) {
                power_backlight_on(++new_brightness);
                gui_update_text(item_text, LABELS[new_brightness - 1]);
            }
            break;

        default:
            done = (ev_id == gui_get_click_event());
        }
    }

    // Persist updated preferences
    if (new_brightness != initial_brightness) {
        storage_set_brightness(new_brightness);
    }
}
#endif

static void update_idle_timeout_text(gui_view_node_t* timeout_text, const uint16_t timeout)
{
    JADE_ASSERT(timeout_text);
    char txt[16];

    // Prefer to display in minutes
    if (timeout == UINT16_MAX) {
        const int ret = snprintf(txt, sizeof(txt), "Disabled");
        JADE_ASSERT(ret > 0 && ret < sizeof(txt));
    } else if (timeout == 60) {
        const int ret = snprintf(txt, sizeof(txt), "1 minute");
        JADE_ASSERT(ret > 0 && ret < sizeof(txt));
    } else if (timeout % 60 == 0) {
        const int ret = snprintf(txt, sizeof(txt), "%u minutes", timeout / 60);
        JADE_ASSERT(ret > 0 && ret < sizeof(txt));
    } else {
        const int ret = snprintf(txt, sizeof(txt), "%u seconds", timeout);
        JADE_ASSERT(ret > 0 && ret < sizeof(txt));
    }
    gui_update_text(timeout_text, txt);
}

static void handle_idle_timeout(void)
{
    static const uint16_t VALUES[] = {
        60, 120, 180, 300, 600, 900, 1200, 1800, 3600, UINT16_MAX // UINT16_MAX == OFF
    };
    static const uint16_t num_values = sizeof(VALUES) / sizeof(VALUES[0]);

    // Get/track the idle timeout
    const uint16_t initial_timeout = storage_get_idle_timeout();
    uint16_t new_timeout = initial_timeout;

    // Find the position in the list of allowed values
    // (NOTE: UINT16_MAX as final value prevents off-the-end)
    uint8_t pos = 0;
    while (VALUES[pos] < new_timeout) {
        ++pos;
    }

    gui_view_node_t* item_text = NULL;
    gui_activity_t* const act = make_carousel_activity("Idle Timeout", NULL, &item_text);
    JADE_ASSERT(item_text);
    update_idle_timeout_text(item_text, new_timeout);
    gui_set_current_activity(act);

    int32_t ev_id;
    bool done = false;
    while (!done) {
        // wait for a GUI event
        gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case GUI_WHEEL_LEFT_EVENT:
            pos = (pos + num_values - 1) % num_values;
            new_timeout = VALUES[pos];
            update_idle_timeout_text(item_text, new_timeout);
            break;

        case GUI_WHEEL_RIGHT_EVENT:
            pos = (pos + 1) % num_values;
            new_timeout = VALUES[pos];
            update_idle_timeout_text(item_text, new_timeout);
            break;

        default:
            done = (ev_id == gui_get_click_event());
        }
    }

    // Persist updated preferences
    if (new_timeout != initial_timeout) {
        storage_set_idle_timeout(new_timeout);
    }
}

static void handle_pinserver_scan(void)
{
    if (keychain_has_pin()) {
        // Not allowed if wallet initialised
        await_error_activity("\n       Set Oracle not\n       permitted once\n      wallet initialized");
        return;
    }

    char* type;
    uint8_t* data = NULL;
    size_t data_len = 0;
    if (!bcur_scan_qr("Scan Oracle\n      QR", &type, &data, &data_len, "blkstrm.com/oracle")) {
        // Scan aborted
        JADE_ASSERT(!type);
        JADE_ASSERT(!data);
        return;
    }

    if (!type || strcasecmp(type, BCUR_TYPE_JADE_UPDPS) || !data || !data_len) {
        await_error_activity("Failed to parse Oracle data");
        goto cleanup;
    }

    if (!handle_update_pinserver_qr(data, data_len)) {
        JADE_LOGD("Failed to persist Oracle details");
        goto cleanup;
    }
    await_message_activity("Oracle details updated!");

cleanup:
    free(type);
    free(data);
}

static void handle_pinserver_reset(void)
{
    if (keychain_has_pin()) {
        // Not allowed if wallet initialised
        await_error_activity("\n      Reset Oracle not\n       permitted once\n      wallet initialized");
        return;
    }

    if (await_yesno_activity("Reset Oracle", "\nReset Oracle details\nand certificate?", false, NULL)) {
        if (!reset_pinserver()) {
            await_error_activity("Error resetting Oracle");
        }
    }
}

// Device info
static void handle_storage(void)
{
    size_t entries_used, entries_free;
    if (!storage_get_stats(&entries_used, &entries_free)) {
        await_error_activity("Error accessing storage!");
        return;
    }

    gui_activity_t* const act = make_storage_stats_activity(entries_used, entries_free);
    gui_set_current_activity(act);
    while (
        !gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_SETTINGS_DEVICE_INFO_STORAGE_EXIT, NULL, NULL, NULL, 0)) {
        // await button press
    }
}

static void handle_info_detail_screen(const char* title, const char* detail)
{
    JADE_ASSERT(title);
    JADE_ASSERT(detail);

    const bool show_help_btn = false;
    gui_activity_t* const act = make_show_single_value_activity(title, detail, show_help_btn);
    gui_set_current_activity(act);
    while (!gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_BACK, NULL, NULL, NULL, 0)) {
        // await button press
    }
}

static void handle_display_fwversion(void) { handle_info_detail_screen("Firmware Version", running_app_info.version); }

static void handle_display_mac_address(void)
{
    char mac[18] = "NO BLE";
#ifdef CONFIG_BT_ENABLED
    const int rc = ble_get_mac(mac, sizeof(mac));
    JADE_ASSERT(rc == 18);
#endif

    handle_info_detail_screen("MAC Address", mac);
}

static void handle_display_battery_volts(void)
{
    char power_status[32] = "NO BAT";
#ifdef CONFIG_HAS_AXP
    const int ret = snprintf(power_status, sizeof(power_status), "%umv", power_get_vbat());
    JADE_ASSERT(ret > 0 && ret < sizeof(power_status));
#elif defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY) || defined(CONFIG_BOARD_TYPE_M5_FIRE)
    const float approx_voltage = power_get_vbat() / 1000.0;
    const int ret = snprintf(power_status, sizeof(power_status), "Approx %.1fv", approx_voltage);
    JADE_ASSERT(ret > 0 && ret < sizeof(power_status));
#endif

    handle_info_detail_screen("Battery Volts", power_status);
}

// Create the appropriate 'Settings' menu
static gui_activity_t* create_settings_menu(const bool startup_menu)
{
    gui_activity_t* act = NULL;
    if (startup_menu) {
        // Startup (click on spalsh screen) menu
        act = make_startup_options_activity();
    } else if (keychain_get()) {
        // Unlocked Jade - main settings
        act = make_unlocked_settings_activity();
    } else if (keychain_has_pin()) {
        // Locked Jade - before pin entry when saved wallet exists
        act = make_locked_settings_activity();
    } else {
        // Uninitilised Jade - no wallet set
        act = make_uninitialised_settings_activity();
    }
    return act;
}

static void handle_settings(const bool startup_menu)
{
    // Create the appropriate 'Settings' menu
    gui_activity_t* act = create_settings_menu(startup_menu);

    // Only show BLE settings if a) unit unlocked or b) unit uninitialised
    const bool show_ble_settings = keychain_get() || !keychain_has_pin();

    // hw uninitialised and not unlocked (eg. as temporary signer)
    const bool hw_locked_uninitialised = !keychain_get() && !keychain_has_pin();

    // NOTE: menu navigation frees prior screens, as the navigation is
    // potentially unbound with all the back and forward buttons.
    bool done = false;
    while (!done) {
        gui_set_current_activity_ex(act, true);

        int32_t ev_id;
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {

        case BTN_SETTINGS_EXIT:
            done = true;
            break;

        case BTN_SETTINGS_DEVICE_EXIT:
        case BTN_SETTINGS_WALLET_EXIT:
        case BTN_SETTINGS_AUTHENTICATION_EXIT:
        case BTN_SETTINGS_PINSERVER_EXIT:
            // Change to base 'Settings' menu
            act = create_settings_menu(startup_menu);
            break;

        case BTN_SETTINGS_WALLET:
            // Change to 'Wallet' menu
            act = make_wallet_settings_activity();
            break;

        case BTN_SETTINGS_DEVICE:
        case BTN_SETTINGS_INFO_EXIT:
            // Change to 'Device' menu
            act = make_device_settings_activity();
            break;

        case BTN_SETTINGS_PREFS_EXIT:
            // Change to 'Device' menu (or 'uninitialised options' menu)
            act = hw_locked_uninitialised ? make_uninitialised_settings_activity() : make_device_settings_activity();
            break;

        case BTN_SETTINGS_INFO:
        case BTN_SETTINGS_DEVICE_INFO_EXIT:
            // Change to 'Info' menu
            act = make_info_activity(running_app_info.version);
            break;

        case BTN_SETTINGS_DEVICE_INFO:
            // Change to 'Device' menu
            act = make_device_info_activity();
            break;

        case BTN_SETTINGS_PREFS:
            // Change to 'Preferences' menu (Settings)
            act = make_prefs_settings_activity(show_ble_settings);
            break;

        case BTN_SETTINGS_AUTHENTICATION:
        case BTN_SETTINGS_OTP_EXIT:
            // Change to 'Authentication' menu
            act = make_authentication_activity();
            break;

        case BTN_SETTINGS_OTP:
        case BTN_SETTINGS_OTP_NEW_EXIT:
            // Change to 'OTP' menu
            act = make_otp_activity();
            break;

        case BTN_SETTINGS_OTP_NEW:
            // Change to 'New OTP' menu
            act = make_new_otp_activity();
            break;

        case BTN_SETTINGS_PINSERVER:
            // Change to 'PinServer' menu
            act = make_pinserver_activity();
            break;

        // Screen handling
        case BTN_SETTINGS_INFO_FWVERSION:
            handle_display_fwversion();
            break;

        case BTN_SETTINGS_DEVICE_INFO_MAC:
            handle_display_mac_address();
            break;

        case BTN_SETTINGS_DEVICE_INFO_BATTERY:
            handle_display_battery_volts();
            break;

        case BTN_SETTINGS_DEVICE_INFO_STORAGE:
            handle_storage();
            break;

        case BTN_SETTINGS_BLE:
            handle_ble();
            break;

// NOTE: Only Jade v1.1's have brightness controls
#ifdef CONFIG_BOARD_TYPE_JADE_V1_1
        case BTN_SETTINGS_SCREEN_BRIGHTNESS:
            handle_screen_brightness();
            break;
#endif

        case BTN_SETTINGS_IDLE_TIMEOUT:
            handle_idle_timeout();
            break;

        case BTN_SETTINGS_BIP39_PASSPHRASE:
            // persist settings in storage
            handle_passphrase_prefs();
            break;

        case BTN_SETTINGS_MULTISIG:
            handle_multisigs();
            break;

        case BTN_SETTINGS_WALLET_ERASE_PIN:
            handle_wallet_erase_pin();
            break;

        case BTN_SETTINGS_RESET:
            offer_jade_reset();
            break;

        case BTN_SETTINGS_XPUB_EXPORT:
            display_xpub_qr();
            break;

        case BTN_SETTINGS_BIP85:
            handle_bip85_mnemonic();
            break;

        case BTN_SETTINGS_QR_PINSERVER:
            // If the user starts the process of interacting with the pinserver via QR codes we must break out
            // here and not go back to the menu, as a) the 'auth_user' and pinserver messages need to be handled
            // asap, and b) the process may have invalidated the menu screens/activities we are using here.
            // ofc if the user declines starting the process, staying in the loop is fine/correct.
            done = offer_pinserver_qr_unlock();
            break;

        case BTN_SETTINGS_TEMPORARY_WALLET_LOGIN:
            // If the user starts the process of creating a temporary wallet, we must break out here and not
            // go back to the menu, as a) the 'auth_user' message probably needs to be handled asap, and b) the
            // setup process may have invalidated the menu screens/activities we are using in this loop.
            // ofc if the user declines starting the process, staying in the loop is fine/correct.
            done = offer_temporary_wallet_login();
            break;

        case BTN_SETTINGS_OTP_VIEW:
            handle_view_otps();
            break;

        case BTN_SETTINGS_OTP_NEW_QR:
            register_otp_qr();
            break;

        case BTN_SETTINGS_OTP_NEW_KB:
            register_otp_kb_entry();
            break;

        case BTN_SETTINGS_PINSERVER_SHOW:
            show_pinserver_details();
            break;

        case BTN_SETTINGS_PINSERVER_SCAN_QR:
            handle_pinserver_scan();
            break;

        case BTN_SETTINGS_PINSERVER_RESET:
            handle_pinserver_reset();
            break;

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        case BTN_SETTINGS_LEGAL:
            handle_legal();
            break;
#endif

        // Help screens
        case BTN_SETTINGS_PINSERVER_HELP:
            await_qr_help_activity("blkstrm.com/oracle");
            break;

        case BTN_SETTINGS_OTP_HELP:
            await_qr_help_activity("blkstrm.com/otp");
            break;

        default:
            // Unexpected event, just ignore
            break;
        }
    }
}

void offer_startup_options(void)
{
    const bool is_startup_menu = true;
    handle_settings(is_startup_menu);
}

// Session logout or sleep/power-off
static void handle_session(void)
{
    gui_activity_t* const act = make_session_activity();
    int32_t ev_id;

    while (true) {
        gui_set_current_activity(act);
        if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            switch (ev_id) {
            case BTN_SESSION_LOGOUT:
                // Logout of current wallet, delete keychain
                keychain_clear();
                return;

            case BTN_SESSION_SLEEP:
                // Shutdown Jade
                power_shutdown();
                return;

            case BTN_SESSION_EXIT:
                return;

            default:
                break;
            }
        }
    }
}

// Scan seedqr and log in for qr (only) mode
static bool qr_mode_scan_seedqr(void)
{
    const bool temporary_restore = true;
    const bool force_qr_scan = true;
    initialise_with_mnemonic(temporary_restore, force_qr_scan);
    if (!keychain_get()) {
        return false;
    }

    return offer_pinserver_via_qr(temporary_restore);
}

static void handle_qr_mode(void)
{
    gui_activity_t* const act = make_connect_qrmode_activity(device_name);
    int32_t ev_id;

    bool done = false;
    while (!done) {
        gui_set_current_activity(act);
        if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            switch (ev_id) {
            case BTN_CONNECT_QR_PIN:
                done = offer_pinserver_qr_unlock();
                break;

            case BTN_CONNECT_QR_SCAN:
                done = qr_mode_scan_seedqr();
                break;

            case BTN_CONNECT_HELP:
                await_qr_help_activity("blkstrm.com/qrmode");
                break;

            case BTN_CONNECT_BACK:
                done = true;
                break;
            }
        }
    }
}

// Process buttons on the dashboard screen
static void handle_btn(const int32_t btn)
{
    switch (btn) {
    case BTN_INITIALIZE:
        initialise_wallet(false);
        break;

    case BTN_SCAN_SEEDQR:
        qr_mode_scan_seedqr();
        break;

    case BTN_CONNECT_TO_BACK:
        select_initial_connection(keychain_has_temporary());
        break;

    case BTN_QR_MODE:
        handle_qr_mode();
        break;

    case BTN_SESSION:
        handle_session();
        break;

    case BTN_SETTINGS:
        handle_settings(false);
        break;

    case BTN_SCAN_QR:
        handle_scan_qr();
        break;

    // The 'connect' screen
    case BTN_CONNECT:
        show_connect_screen = true;
        break;

    case BTN_CONNECT_BACK:
        show_connect_screen = false;
        break;

    case BTN_CONNECT_HELP:
        await_qr_help_activity("blkstrm.com/jadewallets");
        break;

    default:
        break;
    }
}

// Display the passed dashboard screen
static void display_screen(jade_process_t* process, gui_activity_t* act)
{
    JADE_ASSERT(process);
    JADE_ASSERT(act);

    // Print the main stack usage (high water mark), and the DRAM usage
    JADE_LOGI("Main task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
    JADE_LOGI("DRAM block / free: %u / %u", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL),
        heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));

    // Switch to passed screen, and at that point free all other managed activities
    // Should be no-op if we didn't switch away from this screen
    gui_set_current_activity_ex(act, true);

    // Refeed sensor entropy every time we return to dashboard screen
    const TickType_t tick_count = xTaskGetTickCount();
    refeed_entropy((const uint8_t*)&tick_count, sizeof(tick_count));
}

// Display the dashboard ready or welcome screen.  Await messages or user GUI input.
static void do_dashboard(jade_process_t* process, const keychain_t* const initial_keychain, const bool initial_has_pin,
    gui_activity_t* act_dashboard, wait_event_data_t* event_data)
{
    JADE_ASSERT(process);
    JADE_ASSERT(act_dashboard);
    JADE_ASSERT(event_data);

    // Loop all the time the keychain is unchanged, awaiting either a message
    // from companion app or a GUI interaction from the user
    bool acted = true;
    const bool initial_ble = ble_connected();
    const bool initial_usb = usb_connected();
    const uint8_t initial_userdata = keychain_get_userdata();
    const jade_msg_source_t initial_connection_selection = initialisation_source;
    const bool initial_show_connect_screen = show_connect_screen;

    while (keychain_get() == initial_keychain && keychain_has_pin() == initial_has_pin
        && keychain_get_userdata() == initial_userdata && initial_show_connect_screen == show_connect_screen
        && initialisation_source == initial_connection_selection) {
        // If the last loop did something, ensure the current dashboard screen
        // is displayed. (Doing this too eagerly can either cause unnecessary
        // screen flicker or can cause the dashboard to overwrite other screens
        // eg. BLE pairing/bonding confirm screen.)
        if (acted) {
            display_screen(process, act_dashboard);
        }

        // Fresh iteration
        acted = false;

        // 1. Process any message if available (do not block if no message available)
        jade_process_load_in_message(process, false);
        if (process->ctx.cbor) {
            dispatch_message(process);
            acted = true;
        }

        // 2. Process any outstanding GUI event if we didn't process a message (again, don't block)
        const char* ev_base;
        int32_t ev_id;
        if (!acted) {
            if (sync_wait_event(event_data, &ev_base, &ev_id, NULL, 100 / portTICK_PERIOD_MS) == ESP_OK) {
                if (show_connect_screen && ev_base == GUI_BUTTON_EVENT) {
                    // Normal button press from some other home-like screen
                    // (eg. connect/connect-to screens etc)
                    handle_btn(ev_id);
                    acted = true;
                } else if (ev_base == GUI_EVENT) {
                    // Low-level gui event from the generic home screen
                    const size_t nbtns = sizeof(home_menu_items[0]) / sizeof(home_menu_items[0][0]);
                    const home_menu_item_t* menu_item = NULL;
                    if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                        // Back, but skip over any unused menu-item entries (null text)
                        do {
                            home_screen_menu_item = (home_screen_menu_item + nbtns - 1) % nbtns;
                            menu_item = get_selected_home_screen_menu_item();
                        } while (!menu_item->text);
                        update_home_screen_menu();
                    } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                        // Next, but skip over any unused menu-item entries (null text)
                        do {
                            home_screen_menu_item = (home_screen_menu_item + 1) % nbtns;
                            menu_item = get_selected_home_screen_menu_item();
                        } while (!menu_item->text);
                        update_home_screen_menu();
                    } else if (ev_id == gui_get_click_event()) {
                        // Click - handle the current button's event
                        menu_item = get_selected_home_screen_menu_item();
                        handle_btn(menu_item->btn_id);
                        acted = true;
                    }
                }
            }
        }

        // If we did some action this loop, run housekeeping
        if (acted) {
            // Cleanup anything attached to the dashboard process
            cleanup_jade_process(process);

            // Assert all sensitive memory was zero'd
            sensitive_assert_empty();
        }

        // Ensure to clear any decrypted keychain if ble- or usb- connection status changes.
        // NOTE: if this clears a populated keychain then this loop will complete
        // and cause this function to return.
        // NOTE: only applies to a *peristed* keychain - ie if we have a pin set, and *NOT*
        // if this is a temporary/emergency-restore wallet.
        if (initial_has_pin && initial_keychain && !keychain_has_temporary()) {
            if (ble_connected() != initial_ble || usb_connected() != initial_usb) {
                JADE_LOGI("Connection status changed - clearing keychain");
                keychain_clear();
            }
        }
    }
}

#define UPDATE_HOME_SCREEN(screen_type)                                                                                \
    do {                                                                                                               \
        home_screen_type = screen_type;                                                                                \
        home_screen_menu_item = 0;                                                                                     \
        update_home_screen(status_light, status_text, label);                                                          \
        update_home_screen_menu();                                                                                     \
    } while (false)

// Main/default screen/process when ready for user interaction
void dashboard_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    ASSERT_NO_CURRENT_MESSAGE(process);

    // At startup we expect no keychain
    JADE_ASSERT(!keychain_get());

    // Populate the static fields about the unit/fw
    device_name = get_jade_id();
    JADE_ASSERT(device_name);

    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_ASSERT(running);
    const esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
    JADE_ASSERT(err == ESP_OK);

    // NOTE: Create 'Ready' screen for when Jade is unlocked and ready to use early, so that
    // it does not fragment the RAM (since it is long-lived).
    // NOTE: The main home screen is created as an 'unmanaged' activity, so it is not placed
    // in the list of activities to be freed by 'set_current_activity_ex()' calls.
    // This is desirable as this screen is never freed and lives as long as the application.

    // NOTE: the menu nodes are static, so we can update the menu displayed when teh user scrolls
    gui_view_node_t* status_light = NULL;
    gui_view_node_t* status_text = NULL;
    gui_view_node_t* label = NULL;
    gui_activity_t* const act_home = make_home_screen_activity(device_name, running_app_info.version,
        &home_screen_item_symbol, &home_screen_item_text, &status_light, &status_text, &label);
    JADE_ASSERT(home_screen_item_symbol);
    JADE_ASSERT(home_screen_item_text);
    JADE_ASSERT(status_light);
    JADE_ASSERT(status_text);
    JADE_ASSERT(label);

    // We may as well associate the long-lived event data with this activity also
    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(act_home);
    JADE_ASSERT(event_data);

    // Register for all events on the home screen
    gui_activity_register_event(act_home, GUI_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    while (true) {
        // Create/set current 'dashboard' screen, then process all events until that
        // dashboard is no longer appropriate - ie. until the keychain is set (or unset).
        // We have six cases:
        // 1. Ready - has keys already associated with a message source
        //    - ready screen  (created early and persistent, see above)
        // 2. Awaiting QR intialisation - this is a special case of either 3. or 4. below
        //    - just show 'Processing...' screen while we await QR client task
        // 3. Unused keys - has keys in memory, but not yet connected to an app
        //    - connect-to screen
        // 4. Locked - has persisted/encrypted keys, but no keys in memory
        //    - welcome-back screen
        // 5. Connect - as above, but user has clicked into the explanatory 'connect' screen
        //    - connect screen
        // 6. Uninitialised - has no persisted/encrypted keys and no keys in memory
        //    - setup screen
        gui_activity_t* act_dashboard = NULL;
        const bool has_pin = keychain_has_pin();
        const keychain_t* initial_keychain = keychain_get();

        if (show_connect_screen) {
            // Some sort of connection is in progress
            if (initialisation_source == SOURCE_QR) {
                JADE_LOGI("Awaiting QR initialisation");
                act_dashboard = display_processing_message_activity();
            } else if (initial_keychain) {
                JADE_LOGI("Wallet/keys initialised but not yet saved - showing Connect-To screen");
                act_dashboard = make_connect_to_activity(device_name, initialisation_source);
                gui_activity_register_event(
                    act_dashboard, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);
            } else {
                JADE_LOGI("User navigated to 'connect' screen");
                act_dashboard = make_connect_activity(device_name);
                gui_activity_register_event(
                    act_dashboard, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);
            }
        } else {
            // Show home screen
            if (initial_keychain && keychain_get_userdata() != SOURCE_NONE) {
                JADE_LOGI("Connected and have wallet/keys - showing home screen/Active");
                UPDATE_HOME_SCREEN(HOME_SCREEN_TYPE_ACTIVE);
            } else if (has_pin) {
                JADE_LOGI("Wallet/keys pin set but not yet loaded - showing home screen/Initialised");
                UPDATE_HOME_SCREEN(HOME_SCREEN_TYPE_LOCKED);
            } else {
                JADE_LOGI("No wallet/keys and no pin set - showing home screen/Uninitialised");
                UPDATE_HOME_SCREEN(HOME_SCREEN_TYPE_UNINIT);
            }
            act_dashboard = act_home;
        }

        // This call loops/blocks all the time the user keychain (and related details)
        // remains unchanged.  When it changes we go back round this loop setting
        // a new 'dashboard' screen and re-running the dashboard processing loop.
        // NOTE: connecting or disconnecting serial or ble will cause any keys to
        // be cleared (and bzero'd).
        do_dashboard(process, initial_keychain, has_pin, act_dashboard, event_data);
    }
}
