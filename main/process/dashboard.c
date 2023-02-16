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
#include "../selfcheck.h"
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
#ifndef CONFIG_ESP32_NO_BLOBS
#include "../ble/ble.h"
#else
// Stubs
static inline bool ble_enabled(void) { return false; }
static inline bool ble_connected(void) { return false; }
static inline void ble_start(void) { JADE_ASSERT(false); }
#endif
#include "process/ota_defines.h"
#include "process_utils.h"

#include <sodium/utils.h>
#include <time.h>

// Whether during initialisation we select USB, BLE QR etc.
static jade_msg_source_t initialisation_source = SOURCE_NONE;

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
#endif
void ota_process(void* process_ptr);
void ota_delta_process(void* process_ptr);
void update_pinserver_process(void* process_ptr);
void auth_user_process(void* process_ptr);

// GUI screens
void make_setup_screen(gui_activity_t** activity_ptr, const char* device_name, const char* firmware_version);
void make_connect_screen(gui_activity_t** activity_ptr, const char* device_name, const char* firmware_version);
void make_connection_select_screen(gui_activity_t** activity_ptr, bool temporary_restore);
void make_connect_to_screen(
    gui_activity_t** activity_ptr, const char* device_name, jade_msg_source_t initialisation_source);
void make_ready_screen(
    gui_activity_t** activity_ptr, const char* device_name, gui_view_node_t** txt_label, gui_view_node_t** txt_extra);

void make_startup_options_screen(gui_activity_t** activity_ptr);
void make_uninitialised_settings_screen(gui_activity_t** activity_ptr);
void make_locked_settings_screen(gui_activity_t** activity_ptr);
void make_unlocked_settings_screen(gui_activity_t** activity_ptr);

void make_wallet_settings_screen(gui_activity_t** activity_ptr);
void make_advanced_options_screen(gui_activity_t** activity_ptr);
void make_device_settings_screen(gui_activity_t** activity_ptr, gui_view_node_t** timeout_btn_text);
void make_idle_timeout_screen(gui_activity_t** activity_ptr, btn_data_t* timeout_btns, const size_t nBtns);

void make_wallet_erase_pin_info_activity(gui_activity_t** activity_ptr);
void make_wallet_erase_pin_options_activity(gui_activity_t** activity_ptr, const char* pinstr);

void make_passphrase_prefs_screen(
    gui_activity_t** activity_ptr, gui_view_node_t** frequency_textbox, gui_view_node_t** method_textbox);

void make_otp_screen(gui_activity_t** activity_ptr);
void make_view_otp_activity(
    gui_activity_t** activity_ptr, size_t index, size_t total, bool valid, const otpauth_ctx_t* ctx);
void make_show_hotp_code_activity(
    gui_activity_t** activity_ptr, const char* name, const char* codestr, bool cancel_button);
void make_show_totp_code_activity(gui_activity_t** activity_ptr, const char* name, const char* timestamp,
    const char* codestr, const bool cancel_button, progress_bar_t* progress_bar, gui_view_node_t** txt_ts,
    gui_view_node_t** txt_code);

void make_pinserver_screen(gui_activity_t** activity_ptr);

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
void make_legal_screen(gui_activity_t** activity_ptr);
#endif
void make_storage_stats_screen(gui_activity_t** activity_ptr, size_t entries_used, size_t entries_free);

void make_session_screen(gui_activity_t** activity_ptr);
void make_ble_screen(gui_activity_t** activity_ptr, const char* device_name, gui_view_node_t** ble_status_textbox);
void make_device_screen(
    gui_activity_t** activity_ptr, const char* power_status, const char* mac, const char* firmware_version);

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
    JADE_ASSERT(ctx == NULL); // Unused here
    JADE_ASSERT(container);

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
        if (keychain_get_userdata() != SOURCE_NONE) {
            add_string_to_map(&map_encoder, "JADE_STATE", "READY");
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
        jade_process_reply_to_message_result(process->ctx, NULL, reply_version_info);
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
        if (debug_selfcheck()) {
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
            || IS_METHOD("get_signature") || IS_METHOD("handshake_init") || IS_METHOD("handshake_complete")) {
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
        }
    }
}

// Function to get user confirmation, then erase all flash memory.
static void offer_jade_reset(void)
{
    // Run 'Reset Jade?'  confirmation screen and wait for yes/no response
    JADE_LOGI("Offering Jade reset");
    const bool bReset = await_yesno_activity("Reset Jade",
        "Do you want to reset Jade and\nclear all PIN and key data?\nThis action cannot be undone!", false);

    if (!bReset) {
        return;
    }

    JADE_LOGI("Yes - requesting numeric confirmation");

    // Force user to confirm a random number
    uint8_t num[PIN_SIZE];
    for (int i = 0; i < PIN_SIZE; ++i) {
        num[i] = get_uniform_random_byte(10);
    }
    char pinstr[sizeof(num) + 1];
    format_pin(pinstr, sizeof(pinstr), num, sizeof(num));

    JADE_LOGI("User must enter: %s to reset all data", pinstr);

    char confirm_msg[64];
    const int ret = snprintf(confirm_msg, sizeof(confirm_msg), "Confirm value to erase all data:\n%20s\n", pinstr);
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
            await_error_activity("Unable to completely reset Jade.");
        }
    } else {
        // Incorrect - continue to boot screen
        JADE_LOGI("User confirmation number incorrect, not wiping data.");
        await_error_activity("Confirmation number incorrect");
    }
}

// Offer to communicate with pinserver via QRs
static bool offer_pinserver_via_qr(const bool temporary_restore)
{
    // User to confirm pinserver-via-QR
    if (!temporary_restore) {
        if (keychain_has_pin()) {
            if (!await_qr_yesno_activity(
                    "QR PIN Unlock", "Visit webpage to\nunlock using QRs", "blockstream.com/pinQR", true)) {
                // User decided against it
                return false;
            }
        } else {
            if (!await_qr_yesno_activity(
                    "QR PIN Setup", "Visit webpage to\nsecure using QRs", "blockstream.com/pinQR", true)) {
                // User decided against it
                return false;
            }
        }
    }

    // Start pinserver/qr handshake process
    initialisation_source = SOURCE_QR;
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

// Screen to select whether the initial connection is via USB or BLE
static void select_initial_connection(const bool temporary_restore)
{
    // Since we have connection options, the user must choose one
    gui_activity_t* activity = NULL;
    make_connection_select_screen(&activity, temporary_restore);
    JADE_ASSERT(activity);

    initialisation_source = SOURCE_NONE;
    do {
        gui_set_current_activity(activity);

        int32_t ev_id;
        // In a debug unattended ci build, assume 'USB' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool ret = gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
        gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool ret = true;
        ev_id = BTN_CONNECT_USB;
#endif

        if (ret) {
            if (ev_id == BTN_CONNECT_USB) {
                // Set USB/SERIAL source
                initialisation_source = SOURCE_SERIAL;
            } else if (ev_id == BTN_CONNECT_BLE) {
                // Set BLE source and ensure ble enabled now and by default
                initialisation_source = SOURCE_BLE;
                if (!ble_enabled()) {
                    const uint8_t ble_flags = storage_get_ble_flags() | BLE_ENABLED;
                    storage_set_ble_flags(ble_flags);
                    ble_start();
                }
            } else if (ev_id == BTN_CONNECT_QR) {
                // Offer pinserver via qr with urls etc
                if (offer_pinserver_via_qr(temporary_restore)) {
                    JADE_ASSERT(initialisation_source == SOURCE_QR);
                }
            }
        }
    } while (initialisation_source == SOURCE_NONE);
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
    if (!await_yesno_activity("Temporary Login",
            "Do you want to temporarily\nlogin using a recovery phrase?\nThis doesn't affect your PIN\nsaved wallet, "
            "if any.",
            true)) {
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
    gui_activity_t* first_activity = NULL;
    make_legal_screen(&first_activity);
    JADE_ASSERT(first_activity);
    gui_set_current_activity(first_activity);

    while (sync_await_single_event(GUI_BUTTON_EVENT, BTN_INFO_EXIT, NULL, NULL, NULL, 0) != ESP_OK) {
        // Wait until we get this event
    }
}
#endif

#ifndef CONFIG_ESP32_NO_BLOBS
// Reset BLE pairing data
static void handle_ble_reset(void)
{
    if (!ble_enabled()) {
        await_message_activity("You must enable Bluetooth\nbefore accessing the pairing\ninformation.");
        return;
    }

    const bool bReset = await_yesno_activity("BLE Reset", "\nDo you want to reset all\nbonded devices?", false);
    if (bReset) {
        if (!ble_remove_all_devices()) {
            await_error_activity("Failed to remove all BLE devices");
        }
    }
}

// BLE properties screen
static inline void update_ble_enabled_text(gui_view_node_t* ble_status_textbox)
{
    gui_update_text(ble_status_textbox, ble_enabled() ? "Enabled" : "Disabled");
}

static void handle_ble(void)
{
    gui_activity_t* act = NULL;
    gui_view_node_t* ble_status_textbox = NULL;
    make_ble_screen(&act, device_name, &ble_status_textbox);
    JADE_ASSERT(act);

    update_ble_enabled_text(ble_status_textbox);
    gui_set_current_activity(act);

    bool loop = true;
    while (loop) {
        int32_t ev_id;
        uint8_t ble_flags;
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case BTN_BLE_EXIT:
            loop = false;
            break;

        case BTN_BLE_TOGGLE_ENABLE:
            ble_flags = storage_get_ble_flags();
            if (ble_enabled()) {
                ble_stop();
                ble_flags &= ~BLE_ENABLED;
            } else {
                ble_start();
                ble_flags |= BLE_ENABLED;
            }
            storage_set_ble_flags(ble_flags);
            update_ble_enabled_text(ble_status_textbox);
            break;

        case BTN_BLE_RESET_PAIRING:
            handle_ble_reset();
            gui_set_current_activity(act);
            break;

        default:
            break;
        }
    }
}
#else
static void handle_ble(void) { await_message_activity("BLE disabled in this firmware"); }
#endif // CONFIG_ESP32_NO_BLOBS

static void handle_multisigs(void)
{
    char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_multisigs = 0;
    bool ok = storage_get_all_multisig_registration_names(names, num_names, &num_multisigs);
    JADE_ASSERT(ok);

    if (num_multisigs == 0) {
        await_message_activity("No m-of-n multisigs registered");
        return;
    }

    for (int i = 0; i < num_multisigs; ++i) {
        const char* errmsg = NULL;
        const char* multisig_name = names[i];
        multisig_data_t multisig_data;
        const bool valid = multisig_load_from_storage(multisig_name, &multisig_data, &errmsg);

        // We will display the names of invalid entries, just log any message
        if (errmsg) {
            JADE_LOGW("%s", errmsg);
        }

        gui_activity_t* act = NULL;
        uint8_t* const master_blinding_key
            = multisig_data.master_blinding_key_len ? multisig_data.master_blinding_key : NULL;
        make_view_multisig_activity(&act, multisig_name, i + 1, num_multisigs, valid, multisig_data.sorted,
            multisig_data.threshold, multisig_data.num_xpubs, master_blinding_key,
            multisig_data.master_blinding_key_len);
        JADE_ASSERT(act);

        while (true) {
            gui_set_current_activity(act);

            int32_t ev_id;
            ok = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
            if (ok && ev_id == BTN_MULTISIG_DELETE) {
                char message[128];
                const int ret = snprintf(message, sizeof(message), "Delete registered multisig?\n\n%s", multisig_name);
                JADE_ASSERT(ret > 0 && ret < sizeof(message));
                if (!await_yesno_activity("Delete Multisig", message, false)) {
                    continue;
                }

                ok = storage_erase_multisig_registration(multisig_name);
                JADE_ASSERT(ok);
            }
            break;
        };
    }
}

static void set_wallet_erase_pin(void)
{
    JADE_LOGI("Requesting wallet-erase PIN");

    // Ask user to enter a wallet-erase pin
    pin_insert_t pin_insert = {};
    make_pin_insert_activity(&pin_insert, "Wallet-Erase PIN", "Enter Wallet-Erase PIN,\ndifferent from unlock PIN");
    JADE_ASSERT(pin_insert.activity);

    while (true) {
        gui_set_current_activity(pin_insert.activity);
        run_pin_entry_loop(&pin_insert);

        // This is the first pin, copy it and clear screen fields
        uint8_t pin[sizeof(pin_insert.pin)];
        memcpy(pin, pin_insert.pin, sizeof(pin));
        clear_current_pin(&pin_insert);

        // Ask user to re-enter PIN
        gui_set_title("Confirm Erase PIN");
        run_pin_entry_loop(&pin_insert);

        // Check that the two pins are the same
        JADE_LOGD("Checking pins match");
        if (!sodium_memcmp(pin, pin_insert.pin, sizeof(pin))) {
            JADE_LOGI("Setting Wallet-Erase PIN");
            storage_set_wallet_erase_pin(pin_insert.pin, sizeof(pin_insert.pin));
            break;
        } else {
            // Pins mismatch - try again
            await_error_activity("Pin mismatch, please try again");
            clear_current_pin(&pin_insert);
        }
    }
}

static void handle_wallet_erase_pin(void)
{
    while (true) {
        // Add wallet erase pin confirmation screens
        uint8_t pin_erase[PIN_SIZE];
        gui_activity_t* act = NULL;
        if (storage_get_wallet_erase_pin(pin_erase, sizeof(pin_erase))) {
            char pinstr[sizeof(pin_erase) + 1];
            format_pin(pinstr, sizeof(pinstr), pin_erase, sizeof(pin_erase));
            make_wallet_erase_pin_options_activity(&act, pinstr);
        } else {
            make_wallet_erase_pin_info_activity(&act);
        }
        JADE_ASSERT(act);
        gui_set_current_activity(act);

        int32_t ev_id;
        if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == BTN_WALLET_ERASE_PIN_SET) {
                // User opted to set a new wallet-erasing PIN
                set_wallet_erase_pin();
                continue;
            } else if (ev_id == BTN_WALLET_ERASE_PIN_DISABLE) {
                // User opted to disable/erase wallet-erasing PIN
                JADE_LOGI("Erasing Wallet-Erase PIN");
                storage_erase_wallet_erase_pin();
                await_message_activity("Wallet-Erase PIN disabled");
            }
        }
        break;
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
    gui_activity_t* activity = NULL;
    gui_view_node_t* frequency_textbox = NULL;
    gui_view_node_t* method_textbox = NULL;
    make_passphrase_prefs_screen(&activity, &frequency_textbox, &method_textbox);
    JADE_ASSERT(activity);
    JADE_ASSERT(frequency_textbox);
    JADE_ASSERT(method_textbox);

    passphrase_freq_t freq = keychain_get_passphrase_freq();
    passphrase_type_t type = keychain_get_passphrase_type();
    while (true) {
        // Update options
        gui_update_text(frequency_textbox, passphrase_frequency_desc_from_flags(freq));
        gui_update_text(method_textbox, passphrase_method_desc_from_flags(type));

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
            if (ev_id == BTN_PASSPHRASE_TOGGLE_FREQUENCY) {
                // Never -> Once -> Always -> Once ...
                freq = (freq == PASSPHRASE_NO     ? PASSPHRASE_ONCE
                        : freq == PASSPHRASE_ONCE ? PASSPHRASE_ALWAYS
                                                  : PASSPHRASE_NO);
            } else if (ev_id == BTN_PASSPHRASE_TOGGLE_METHOD) {
                type = (type == PASSPHRASE_FREETEXT ? PASSPHRASE_WORDLIST : PASSPHRASE_FREETEXT);
            } else if (ev_id == BTN_PASSPHRASE_OPTIONS_HELP) {
                await_qr_help_activity("blockstream.com/passphrase");
            } else if (ev_id == BTN_PASSPHRASE_OPTIONS_EXIT) {
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

// HOTP token-code fixed
static bool display_hotp_screen(const char* name, const char* token, const bool show_cancel_button)
{
    JADE_ASSERT(name);
    JADE_ASSERT(token);

    gui_activity_t* act = NULL;
    make_show_hotp_code_activity(&act, name, token, show_cancel_button);
    JADE_ASSERT(act);

    gui_set_current_activity(act);

    int32_t ev_id;

// In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    const bool btn_pressed = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
#else
    gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
    const bool btn_pressed = true;
    ev_id = BTN_OTP_CONFIRM;
#endif

    return btn_pressed && ev_id == BTN_OTP_CONFIRM;
}

// TOTP token-code display updates with passage of time (unless flagged not to)
static bool display_totp_screen(otpauth_ctx_t* otp_ctx, uint64_t epoch_value, char* token, const size_t token_len,
    const bool show_cancel_button, const bool auto_update)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(otp_ctx->otp_type == OTPTYPE_TOTP);
    JADE_ASSERT(token);

    char timestr[32];
    ctime_r((time_t*)&epoch_value, timestr);

    gui_activity_t* act = NULL;
    gui_view_node_t* txt_ts = NULL;
    gui_view_node_t* txt_code = NULL;
    progress_bar_t time_left = {};
    make_show_totp_code_activity(
        &act, otp_ctx->name, timestr, token, show_cancel_button, &time_left, &txt_ts, &txt_code);
    JADE_ASSERT(act);
    JADE_ASSERT(txt_ts);
    JADE_ASSERT(txt_code);

    gui_set_current_activity(act);

    // Make an event-data structure to track events - attached to the activity
    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(act);
    JADE_ASSERT(event_data);

    // Register for button events
    gui_activity_register_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    // Token code updates with time (unless explicitly specified otherwise - eg. test fixed value)
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    TickType_t timeout = 100 / portTICK_PERIOD_MS;
#endif
    uint8_t count = epoch_value % otp_ctx->period;
    uint8_t last_count = count;
    while (true) {
        int32_t ev_id;

        // In a debug unattended ci build, assume 'accept' button pressed after a short delay
#ifndef CONFIG_DEBUG_UNATTENDED_CI
        const bool btn_pressed
            = sync_wait_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL, timeout) == ESP_OK;
        timeout = 1000 / portTICK_PERIOD_MS; // After initial update, update every 1s
#else
        sync_wait_event(GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL,
            CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
        const bool btn_pressed = true;
        ev_id = BTN_OTP_CONFIRM;
#endif
        // Return if button clicked
        if (btn_pressed) {
            return ev_id == BTN_OTP_CONFIRM;
        }

        // Otherwise update values
        if (auto_update) {
            if (!otp_set_default_value(otp_ctx, &epoch_value)) {
                await_error_activity("Failed to fetch time/counter!");
                return false;
            }
            ctime_r((time_t*)&epoch_value, timestr);
            gui_update_text(txt_ts, timestr);

            count = epoch_value % otp_ctx->period;
            if (count < last_count) {
                // Wrapped - token code should have changed
                if (!otp_get_auth_code(otp_ctx, token, token_len)) {
                    await_error_activity("Failed to calculate OTP!");
                    return false;
                }
                gui_update_text(txt_code, token);
            }
            last_count = count;
        }

        // NOTE: this is outside the 'auto-update' check as the
        // progress-bar needs to be updated at least once.
        update_progress_bar(&time_left, otp_ctx->period, count);
    }
}

bool display_otp_screen(otpauth_ctx_t* otp_ctx, const uint64_t value, char* token, const size_t token_len,
    const bool show_cancel_button, const bool auto_update)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));
    JADE_ASSERT(token);

    if (otp_ctx->otp_type == OTPTYPE_TOTP) {
        // Token code updates with time (unless explicitly specified otherwise - eg. test fixed value)
        return display_totp_screen(otp_ctx, value, token, token_len, show_cancel_button, auto_update);
    } else {
        // NOTE: the 'auto_update' flag is ignored as the hotp counter does not change without
        // the caller making an entirely new 'get token code' request - so the value is fixed.
        // Also, ignore counter value as not displayed.
        return display_hotp_screen(otp_ctx->name, token, show_cancel_button);
    }
}

static void show_otp_code(otpauth_ctx_t* otp_ctx)
{
    JADE_ASSERT(otp_is_valid(otp_ctx));

    // Update context with current default 'moving' element
    uint64_t value = 0;
    if (!otp_set_default_value(otp_ctx, &value)) {
        await_error_activity("Failed to fetch time/counter!");
        return;
    }

    // Calculate token
    char token[OTP_MAX_TOKEN_LEN];
    if (!otp_get_auth_code(otp_ctx, token, sizeof(token))) {
        await_error_activity("Failed to calculate OTP!");
        return;
    }

    // totp token/code updates with time
    const bool auto_update = true;
    const bool show_cancel_button = false;
    display_otp_screen(otp_ctx, value, token, sizeof(token), show_cancel_button, auto_update);
}

static void handle_view_otps(void)
{
    char names[OTP_MAX_RECORDS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_otp_records = 0;
    bool ok = storage_get_all_otp_names(names, num_names, &num_otp_records);
    JADE_ASSERT(ok);

    if (num_otp_records == 0) {
        await_message_activity("No OTP records registered");
        return;
    }

    for (int i = 0; i < num_otp_records; ++i) {
        const char* otp_name = names[i];

        // Load OTP record from storage given the name
        size_t written = 0;
        char otp_uri[OTP_MAX_URI_LEN];
        SENSITIVE_PUSH(otp_uri, sizeof(otp_uri));
        otpauth_ctx_t otp_ctx = { .name = otp_name };
        const bool valid = otp_load_uri(otp_name, otp_uri, sizeof(otp_uri), &written) && written
            && otp_uri_to_ctx(otp_uri, written, &otp_ctx) && otp_is_valid(&otp_ctx);

        // We will display the names of invalid entries, just log any message
        if (!valid) {
            JADE_LOGE("Error loading otp record: %s", otp_name);
        }

        gui_activity_t* act = NULL;
        make_view_otp_activity(&act, i + 1, num_otp_records, valid, &otp_ctx);
        JADE_ASSERT(act);

        while (true) {
            gui_set_current_activity(act);

            int32_t ev_id;
            ok = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);
            if (ok && ev_id == BTN_OTP_DELETE) {
                char message[128];
                const int ret = snprintf(message, sizeof(message), "Delete OTP record?\n\n%s", otp_name);
                JADE_ASSERT(ret > 0 && ret < sizeof(message));
                if (!await_yesno_activity("Delete OTP", message, false)) {
                    continue;
                }

                ok = storage_erase_otp(otp_name);
                JADE_ASSERT(ok);
            } else if (ok && ev_id == BTN_OTP_GENERATE) {
                show_otp_code(&otp_ctx);
                continue;
            }
            break;
        };
        SENSITIVE_POP(otp_uri);
    }
}

static void update_idle_timeout_btns(btn_data_t* timeout_btn, const size_t nBtns, const uint16_t timeout)
{
    JADE_ASSERT(timeout_btn);

    for (int i = 0; i < nBtns; ++i) {
        JADE_ASSERT(timeout_btn[i].btn);
        gui_set_borders(timeout_btn[i].btn, timeout_btn[i].val == timeout ? TFT_BLUE : TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(timeout_btn[i].btn, TFT_BLOCKSTREAM_GREEN);
        gui_repaint(timeout_btn[i].btn, true);
    }
}

static void handle_idle_timeout(uint16_t* const timeout)
{
    JADE_ASSERT(timeout);

    // The idle timeout buttons (1,2,3,5,10,15 mins).
    btn_data_t timeout_btns[] = { { .txt = "1", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TIMEOUT_0, .val = 60 },
        { .txt = "2", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TIMEOUT_0 + 1, .val = 120 },
        { .txt = "3", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TIMEOUT_0 + 2, .val = 180 },
        { .txt = "5", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TIMEOUT_0 + 3, .val = 300 },
        { .txt = "10", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TIMEOUT_0 + 4, .val = 600 },
        { .txt = "15", .font = DEFAULT_FONT, .ev_id = BTN_SETTINGS_TIMEOUT_0 + 5, .val = 900 } };
    const size_t nBtns = sizeof(timeout_btns) / sizeof(btn_data_t);

    // Timeout button ids must be available/contiguous
    JADE_ASSERT(BTN_SETTINGS_TIMEOUT_0 + 5 == BTN_SETTINGS_TIMEOUT_5);

    gui_activity_t* act = NULL;
    make_idle_timeout_screen(&act, timeout_btns, nBtns);
    JADE_ASSERT(act);

    update_idle_timeout_btns(timeout_btns, nBtns, *timeout);
    gui_set_current_activity(act);

    int32_t ev_id;
    const bool res = gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

    if (res && ev_id >= BTN_SETTINGS_TIMEOUT_0 && ev_id < BTN_SETTINGS_TIMEOUT_0 + nBtns) {
        const uint32_t idx = ev_id - BTN_SETTINGS_TIMEOUT_0;

        // Return the updated timeout value
        *timeout = timeout_btns[idx].val;
        storage_set_idle_timeout(*timeout);
    }
}

static void update_idle_timeout_btn_text(gui_view_node_t* timeout_btn_text, const uint16_t timeout)
{
    JADE_ASSERT(timeout_btn_text);
    char txt[32];

    // Prefer to display in minutes
    if (timeout % 60 == 0) {
        const int ret = snprintf(txt, sizeof(txt), "Power-off Timeout (%um)", timeout / 60);
        JADE_ASSERT(ret > 0 && ret < sizeof(txt));
    } else {
        const int ret = snprintf(txt, sizeof(txt), "Power-off Timeout (%us)", timeout);
        JADE_ASSERT(ret > 0 && ret < sizeof(txt));
    }
    gui_update_text(timeout_btn_text, txt);
}

static void handle_pinserver_scan(void)
{
    if (keychain_has_pin()) {
        // Not allowed if wallet initialised
        await_error_activity("Set PinServer not permitted\nonce wallet initialized");
        return;
    }

    char* type;
    uint8_t* data = NULL;
    size_t data_len = 0;
    if (!bcur_scan_qr("Scan QR", "Scan PinServer\ndetails QR", &type, &data, &data_len)) {
        // Scan aborted
        JADE_ASSERT(!type);
        JADE_ASSERT(!data);
        return;
    }

    if (!type || strcasecmp(type, BCUR_TYPE_JADE_UPDPS) || !data || !data_len) {
        await_error_activity("Failed to parse PinServer data");
        goto cleanup;
    }

    if (!handle_update_pinserver_qr(data, data_len)) {
        JADE_LOGD("Failed to persist pinserver details");
        goto cleanup;
    }
    await_message_activity("PinServer details updated!");

cleanup:
    free(type);
    free(data);
}

static void handle_pinserver_reset(void)
{
    if (keychain_has_pin()) {
        // Not allowed if wallet initialised
        await_error_activity("Reset PinServer not permitted\nonce wallet initialized");
        return;
    }

    if (await_yesno_activity("Reset PinServer", "Reset PinServer details\nand certificate?", false)) {
        if (!reset_pinserver()) {
            await_error_activity("Error resetting PinServer");
        }
    }
}

// Create the appropriate 'Settings' menu
static void create_settings_menu(gui_activity_t** activity, const bool startup_menu)
{
    JADE_ASSERT(activity);

    if (startup_menu) {
        // Startup (click on spalsh screen) menu
        make_startup_options_screen(activity);
    } else {
        // Normal 'Settings' menu - depends on wallet state (unlocked, locked, uninitialised)
        if (keychain_get()) {
            // Unlocked Jade - main settings
            make_unlocked_settings_screen(activity);
        } else if (keychain_has_pin()) {
            // Locked Jade - before pin entry when saved wallet exists
            make_locked_settings_screen(activity);
        } else {
            // Uninitilised Jade - no wallet set
            make_uninitialised_settings_screen(activity);
        }
    }
    JADE_ASSERT(*activity);
}

static void handle_settings(const bool startup_menu)
{
    // Get/track the idle timeout
    uint16_t timeout = storage_get_idle_timeout();

    // Create the appropriate 'Settings' menu
    gui_activity_t* act = NULL;
    gui_view_node_t* timeout_btn_text = NULL;
    create_settings_menu(&act, startup_menu);

    bool done = false;
    while (!done) {
        gui_set_current_activity_ex(act, true);

        int32_t ev_id;
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {

        case BTN_SETTINGS_EXIT:
            done = true;
            break;

        case BTN_SETTINGS_ADVANCED_EXIT:
        case BTN_SETTINGS_DEVICE_EXIT:
        case BTN_SETTINGS_WALLET_EXIT:
        case BTN_SETTINGS_PINSERVER_EXIT:
            // Change to base 'Settings' menu
            create_settings_menu(&act, startup_menu);
            timeout_btn_text = NULL;
            break;

        case BTN_SETTINGS_ADVANCED:
        case BTN_SETTINGS_OTP_EXIT:
            // Change to 'Advanced' menu
            make_advanced_options_screen(&act);
            timeout_btn_text = NULL;
            break;

        case BTN_SETTINGS_DEVICE:
            // Change to 'Device' menu
            make_device_settings_screen(&act, &timeout_btn_text);
            update_idle_timeout_btn_text(timeout_btn_text, timeout);
            break;

        case BTN_SETTINGS_WALLET:
            // Change to 'Device' menu
            make_wallet_settings_screen(&act);
            timeout_btn_text = NULL;
            break;

        case BTN_SETTINGS_OTP:
            // Change to 'OTP' menu
            make_otp_screen(&act);
            timeout_btn_text = NULL;
            break;

        case BTN_SETTINGS_PINSERVER:
            // Change to 'PinServer' menu
            make_pinserver_screen(&act);
            timeout_btn_text = NULL;
            break;

        case BTN_SETTINGS_BLE:
            handle_ble();
            break;

        case BTN_SETTINGS_IDLE_TIMEOUT:
            handle_idle_timeout(&timeout);
            update_idle_timeout_btn_text(timeout_btn_text, timeout);
            break;

        case BTN_SETTINGS_PASSPHRASE:
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
    gui_activity_t* act = NULL;
    make_session_screen(&act);
    JADE_ASSERT(act);

    gui_set_current_activity(act);

    int32_t ev_id;
    if (gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
        switch (ev_id) {
        case BTN_SESSION_LOGOUT:
            // Logout of current wallet, delete keychain
            keychain_clear();
            break;

        case BTN_SESSION_SLEEP:
            // Shutdown Jade
            power_shutdown();
            break;

        default:
            break;
        }
    }
}

static void handle_storage(void)
{
    size_t entries_used, entries_free;
    const bool ok = storage_get_stats(&entries_used, &entries_free);
    if (ok) {
        gui_activity_t* act = NULL;
        make_storage_stats_screen(&act, entries_used, entries_free);
        JADE_ASSERT(act);

        gui_set_current_activity(act);
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, BTN_INFO_EXIT, NULL, NULL, NULL, 0);
    } else {
        await_error_activity("Error accessing storage!");
    }
}

// Device info
static void handle_device(void)
{
    char power_status[32] = "NO BAT";
#ifdef CONFIG_HAS_AXP
    const int ret = snprintf(power_status, sizeof(power_status), "%umv", power_get_vbat());
    JADE_ASSERT(ret > 0 && ret < sizeof(power_status));
#endif

    char mac[18] = "NO BLE";
#ifndef CONFIG_ESP32_NO_BLOBS
    const int rc = ble_get_mac(mac, sizeof(mac));
    JADE_ASSERT(rc == 18);
#endif

    gui_activity_t* act = NULL;
    make_device_screen(&act, power_status, mac, running_app_info.version);
    JADE_ASSERT(act);

    bool loop = true;
    while (loop) {
        int32_t ev_id;
        gui_set_current_activity_ex(act, true);
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case BTN_INFO_EXIT:
            loop = false;
            break;

        case BTN_INFO_STORAGE:
            handle_storage();
            break;

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1)
        // For genuine Jade hw, show legal info
        case BTN_INFO_LEGAL:
            handle_legal();
            break;
#endif
        default:
            break;
        }
    }
}

// Process buttons on the dashboard screen
static void handle_btn(const int32_t btn)
{
    switch (btn) {
    case BTN_INITIALIZE:
        return initialise_wallet(false);
    case BTN_CONNECT_BACK:
        return select_initial_connection(keychain_has_temporary());
    case BTN_SESSION:
        return handle_session();
    case BTN_SETTINGS:
        return handle_settings(false);
    case BTN_SCAN_QR:
        return handle_scan_qr();
    case BTN_INFO:
        return handle_device();
    default:
        break;
    }
}

// Display the passed dashboard screen
static void display_screen(jade_process_t* process, gui_activity_t* activity)
{
    JADE_ASSERT(process);
    JADE_ASSERT(activity);

    // Print the main stack usage (high water mark), and the DRAM usage
    JADE_LOGI("Main task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
    JADE_LOGI("DRAM block / free: %u / %u", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL),
        heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));

    // Switch to passed screen, and at that point free all other managed activities
    // Should be no-op if we didn't switch away from this screen
    gui_set_current_activity_ex(activity, true);

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

    while (keychain_get() == initial_keychain && keychain_has_pin() == initial_has_pin
        && keychain_get_userdata() == initial_userdata && initialisation_source == initial_connection_selection) {
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

        // 2. Process any GUI event (again, don't block)
        int32_t ev_id;
        if (!acted
            && sync_wait_event(
                   GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL, 100 / portTICK_PERIOD_MS)
                == ESP_OK) {
            handle_btn(ev_id);
            acted = true;
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

// Helper to create a dashboard activity using the function passed, and then register
// the button event handler which we check if there are no external messages to handle.
#define MAKE_DASHBOARD_SCREEN(fn_make_activity, activity, extra_arg)                                                   \
    do {                                                                                                               \
        fn_make_activity(&activity, device_name, extra_arg);                                                           \
        JADE_ASSERT(activity);                                                                                         \
        gui_activity_register_event(                                                                                   \
            activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);                        \
    } while (false)

// Small helper to update additional info labels on the 'Ready' dashboard screen
static void update_ready_screen_text(gui_view_node_t* txt_label, gui_view_node_t* txt_extra)
{
    JADE_ASSERT(txt_label);
    JADE_ASSERT(txt_extra);

    // Wallet fingerprint in uppercase hex
    char* fphex = NULL;
    uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(fingerprint, sizeof(fingerprint));
    JADE_WALLY_VERIFY(wally_hex_from_bytes(fingerprint, sizeof(fingerprint), &fphex));
    map_string(fphex, toupper);

    char label[20];
    const int ret = snprintf(label, sizeof(label), "Wallet: %s", fphex);
    JADE_ASSERT(ret > 0 && ret <= sizeof(label));
    JADE_WALLY_VERIFY(wally_free_string(fphex));
    gui_update_text(txt_label, label);

    // Extra info under the main wallet label
    const char* const extra = (keychain_get_userdata() == SOURCE_QR ? "(QR Mode)"
            : keychain_has_temporary()                              ? "(Temporary Wallet)"
                                                                    : "");
    gui_update_text(txt_extra, extra);
}

// Wrapper to put calls to free activities onto the process
static void free_unmanaged_activity_wrapper(void* activity_to_free)
{
    gui_activity_t* activity = (gui_activity_t*)activity_to_free;
    free_unmanaged_activity(activity);
}

// Main/default screen/process when ready for user interaction
void dashboard_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    ASSERT_NO_CURRENT_MESSAGE(process);

    // At startup we may have entered an emergency restore mnemonic
    // otherwise we'd expect no keychain at this point.
    JADE_ASSERT(!keychain_get() || keychain_has_temporary());

    // Populate the static fields about the unit/fw
    device_name = get_jade_id();
    JADE_ASSERT(device_name);

    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_ASSERT(running);
    const esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
    JADE_ASSERT(err == ESP_OK);
    wait_event_data_t* const event_data = make_wait_event_data();
    JADE_ASSERT(event_data);

    // NOTE: Create 'Ready' screen for when Jade is unlocked and ready to use early, so that
    // it does not fragment the RAM (since it is long-lived once unit is unlocked with PIN).
    // NOTE: The main 'Ready' screen is created as an 'unmanaged' activity, so it is not placed
    // in the list of activities to be freed by 'set_current_activity_ex()' calls.
    // This is ok as the 'Ready' screen is never freed and lives as long as the application itself.
    gui_activity_t* act_ready = NULL;
    gui_view_node_t* txt_label = NULL;
    gui_view_node_t* txt_extra = NULL;
    make_ready_screen(&act_ready, device_name, &txt_label, &txt_extra);
    JADE_ASSERT(act_ready);
    JADE_ASSERT(txt_label);
    JADE_ASSERT(txt_extra);
    gui_activity_register_event(act_ready, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    while (true) {
        // Create/set current 'dashboard' screen, then process all events until that
        // dashboard is no longer appropriate - ie. until the keychain is set (or unset).
        // We have four cases:
        // 1. Ready - has keys already associated with a message source
        //    - ready screen  (created early and persistent, see above)
        // 2. Awaiting QR intialisation - this is a special case of either 3. or 4. below
        //    - just show 'Processing...' screen while we await QR client task
        // 3. Unused keys - has keys in memory, but not yet connected to an app
        //    - connect-to screen
        // 4. Locked - has persisted/encrypted keys, but no keys in memory
        //    - connect screen
        // 5. Uninitialised - has no persisted/encrypted keys and no keys in memory
        //    - setup screen
        // NOTE: Some dashboard screens are created as 'unmanaged' activities, so are not placed
        // in the list of activities to be freed by 'set_current_activity_ex()' calls, so any
        // 'act_dashboard' created here must be explicitly freed when no longer relevant.
        // 'free_dashboard' is set when this is the case.
        bool free_dashboard = false;
        gui_activity_t* act_dashboard = NULL;
        const bool has_pin = keychain_has_pin();
        const keychain_t* initial_keychain = keychain_get();
        if (initial_keychain && keychain_get_userdata() != SOURCE_NONE) {
            JADE_LOGI("Connected and have wallet/keys - showing Ready screen");
            update_ready_screen_text(txt_label, txt_extra);
            act_dashboard = act_ready;
            // free_dashboard is not required as this screen lives for the lifetime of the application
        } else if (initialisation_source == SOURCE_QR) {
            JADE_LOGI("Awaiting QR initialisation");
            act_dashboard = display_message_activity("Processing...");
            // free_dashboard is not required as this is a standard 'managed' activity
        } else if (initial_keychain) {
            JADE_LOGI("Wallet/keys initialised but not yet saved - showing Connect-To screen");
            MAKE_DASHBOARD_SCREEN(make_connect_to_screen, act_dashboard, initialisation_source);
            // free_dashboard is not required as this is a standard 'managed' activity
        } else if (has_pin) {
            JADE_LOGI("Wallet/keys pin set but not yet loaded - showing Connect screen");
            MAKE_DASHBOARD_SCREEN(make_connect_screen, act_dashboard, running_app_info.version);
            free_dashboard = true;
        } else {
            JADE_LOGI("No wallet/keys and no pin set - showing Setup screen");
            MAKE_DASHBOARD_SCREEN(make_setup_screen, act_dashboard, running_app_info.version);
            free_dashboard = true;
        }

        // This call loops/blocks all the time the user keychain (and related details)
        // remains unchanged.  When it changes we go back round this loop setting
        // a new 'dashboard' screen and re-running the dashboard processing loop.
        // NOTE: connecting or disconnecting serial or ble will cause any keys to
        // be cleared (and bzero'd).
        do_dashboard(process, initial_keychain, has_pin, act_dashboard, event_data);

        // Free (defered slightly) any dashboard screen if flagged as needing explicit free
        if (free_dashboard) {
            jade_process_call_on_exit(process, free_unmanaged_activity_wrapper, act_dashboard);
        }
    }
}
