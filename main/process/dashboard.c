#include <esp_ota_ops.h>
#include <esp_sleep.h>

#include <ctype.h>
#include <string.h>

#include "../button_events.h"
#include "../display.h"
#include "../input.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../power.h"
#include "../process.h"
#include "../qrcode.h"
#include "../random.h"
#include "../selfcheck.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../wallet.h"
#ifndef CONFIG_ESP32_NO_BLOBS
#include "../ble/ble.h"
#endif
#include "process/ota.h"
#include "process_utils.h"

#include <sodium/utils.h>

#define NULLSTRING 1

// Functional actions
void sign_message_process(void* process_ptr);
void sign_tx_process(void* process_ptr);
void get_blinding_key_process(void* process_ptr);
void get_shared_nonce_process(void* process_ptr);
void get_commitments_process(void* process_ptr);
void get_blinding_factor_process(void* process_ptr);
void sign_liquid_tx_process(void* process_ptr);
#ifdef CONFIG_DEBUG_MODE
void debug_set_mnemonic_process(void* process_ptr);
void debug_handshake(void* process_ptr);
#endif
void get_xpubs_process(void* process_ptr);
void get_receive_address_process(void* process_ptr);
void ota_process(void* process_ptr);
void pin_process(void* process_ptr);
void mnemonic_process(void* process_ptr);

// GUI screens
void make_setup_screen(gui_activity_t** act_ptr, const char* device_name);
void make_connect_screen(gui_activity_t** act_ptr, const char* device_name);
void make_ready_screen(gui_activity_t** act_ptr, const char* device_name);
void make_settings_screen(
    gui_activity_t** act_ptr, gui_view_node_t** orientation_textbox, btn_data_t* timeout_btns, const size_t nBtns);
void make_ble_screen(gui_activity_t** act_ptr, const char* device_name, gui_view_node_t** ble_status_textbox);
void make_device_screen(
    gui_activity_t** act_ptr, const char* power_status, const char* mac, const char* firmware_version);

#ifdef CONFIG_DEBUG_MODE
void make_show_xpub(gui_activity_t** act_ptr, Icon* qr_icon);
#endif

static void reply_version_info(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx == NULL); // Unused here
    JADE_ASSERT(container);

    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_ASSERT(running);
    esp_app_desc_t running_app_info;
    const esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
    JADE_ASSERT(err == ESP_OK);

#ifdef CONFIG_DEBUG_MODE
    const uint8_t num_version_fields = 16;
#else
    const uint8_t num_version_fields = 11;
#endif

    CborEncoder map_encoder;
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, num_version_fields);
    JADE_ASSERT(cberr == CborNoError);

    add_string_to_map(&map_encoder, "JADE_VERSION", running_app_info.version);
    add_uint_to_map(&map_encoder, "JADE_OTA_MAX_CHUNK", JADE_OTA_BUF_SIZE);

#ifndef CONFIG_ESP32_NO_BLOBS
    add_string_to_map(&map_encoder, "JADE_CONFIG", "BLE");
#else
    add_string_to_map(&map_encoder, "JADE_CONFIG", "NORADIO");
#endif
    JADE_ASSERT(cberr == CborNoError);

    // Board type - Production Jade, M5Stack, esp32 dev board
#if defined(CONFIG_BOARD_TYPE_JADE)
    add_string_to_map(&map_encoder, "BOARD_TYPE", "JADE");
#elif defined(CONFIG_BOARD_TYPE_M5_FIRE)
    add_string_to_map(&map_encoder, "BOARD_TYPE", "M5FIRE");
#elif defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)
    add_string_to_map(&map_encoder, "BOARD_TYPE", "M5BLACKGRAY");
#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY)
    add_string_to_map(&map_encoder, "BOARD_TYPE", "TTGO_TDISPLAY");
#elif defined(CONFIG_BOARD_TYPE_DEV)
    add_string_to_map(&map_encoder, "BOARD_TYPE", "DEV");
#else
    add_string_to_map(&map_encoder, "BOARD_TYPE", "UNKNOWN");
#endif
    JADE_ASSERT(cberr == CborNoError);

    // 'features' could potentially be a comma-separated list
    // initially it's either 'secure boot' or 'dev' ...
#ifdef CONFIG_SECURE_BOOT
    add_string_to_map(&map_encoder, "JADE_FEATURES", "SB");
#else
    add_string_to_map(&map_encoder, "JADE_FEATURES", "DEV");
#endif

    JADE_ASSERT(cberr == CborNoError);
    const char* idfversion = esp_get_idf_version();
    add_string_to_map(&map_encoder, "IDF_VERSION", idfversion);

    esp_chip_info_t info;
    esp_chip_info(&info);

    char* hexstr = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes((unsigned char*)&info.features, 4, &hexstr));
    add_string_to_map(&map_encoder, "CHIP_FEATURES", hexstr);

    wally_free_string(hexstr);

    uint8_t macid[6];
    esp_efuse_mac_get_default(macid);
    JADE_WALLY_VERIFY(wally_hex_from_bytes(macid, 6, &hexstr));
    for (size_t i = 0; i < strlen(hexstr); ++i) {
        hexstr[i] = toupper((int)hexstr[i]);
    }
    add_string_to_map(&map_encoder, "EFUSEMAC", hexstr);
    wally_free_string(hexstr);

    const char* state = keychain_get() != NULL ? "READY" : keychain_has_pin() ? "LOCKED" : "UNINIT";
    add_string_to_map(&map_encoder, "JADE_STATE", state);

    const network_type_t restriction = storage_get_network_type_restriction();
    const char* networks = restriction == MAIN ? "MAIN" : restriction == TEST ? "TEST" : "ALL";
    add_string_to_map(&map_encoder, "JADE_NETWORKS", networks);

    // Deprecated (as of 0.1.25) - to be removed later
    add_boolean_to_map(&map_encoder, "JADE_HAS_PIN", keychain_has_pin());

// Memory stats only needed in DEBUG
#ifdef CONFIG_DEBUG_MODE
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

// Do we have have a keychain, and does its userdata indicate the same 'source'
// as the current message ?
// This is to check that we only handle messages from the same source (serial or ble)
// as initially unlocked the key material.
static inline bool keychain_unlocked_by_message_source(jade_process_t* process)
{
    return keychain_get() && keychain_get_userdata() == (uint8_t)process->ctx.source;
}

// Minimal auth-user call for when keychain already unlocked
// Just checks passed network type is valid.
static void auth_user_minimal(jade_process_t* process)
{
    ASSERT_CURRENT_MESSAGE(process, "auth_user");
    JADE_ASSERT(keychain_get());

    char network[strlen(TAG_LOCALTESTLIQUID) + 1];
    GET_MSG_PARAMS(process);

    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);

    // All good, reply ok
    jade_process_reply_to_message_ok(process);

cleanup:
    return;
}

// method_name should be a string literal - or at least non-null and null-terminated
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
    } else if (IS_METHOD("auth_user")) {
        // Either enter pin or set-up mnemonic if uninitialised
        if (keychain_unlocked_by_message_source(process)) {
            JADE_LOGD("auth_user called - keychain already unlocked, minimal checks");
            auth_user_minimal(process);
        } else if (keychain_has_pin()) {
            JADE_LOGD("auth_user called - keychain locked, requesting pin");
            task_function = pin_process;
        } else {
            JADE_LOGD("auth_user called - no wallet data, requesting mnemonic");
            task_function = mnemonic_process;
        }
    } else if (IS_METHOD("ota")) {
        // OTA is allowed if either:
        // a) User has passed PIN screen and has unlocked Jade
        // or
        // b) There is no PIN set (ie. no encrypted keys set, eg. new device)
        if (keychain_unlocked_by_message_source(process) || !keychain_has_pin()) {
            task_function = ota_process;
        } else {
            // Reject the message as bad (ota) protocol
            jade_process_reject_message(
                process, CBOR_RPC_HW_LOCKED, "OTA is only allowed on new or logged-in device.", NULL);
        }
#ifdef CONFIG_DEBUG_MODE
    } else if (IS_METHOD("debug_selfcheck")) {
        if (debug_selfcheck(process)) {
            jade_process_reply_to_message_ok(process);
        } else {
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "ERROR", NULL);
        }
    } else if (IS_METHOD("debug_set_mnemonic")) {
        task_function = debug_set_mnemonic_process;
    } else if (IS_METHOD("debug_handshake")) {
        task_function = debug_handshake;
#endif // CONFIG_DEBUG_MODE
    } else {
        // Methods only available after user authorised
        if (!keychain_unlocked_by_message_source(process)) {
            // Reject the message as bad (startup) protocol
            jade_process_reject_message(
                process, CBOR_RPC_HW_LOCKED, "When locked expecting either 'auth_user' or 'ota' message only.", NULL);
        } else if (IS_METHOD("get_xpub")) {
            task_function = get_xpubs_process;
        } else if (IS_METHOD("get_receive_address")) {
            task_function = get_receive_address_process;
        } else if (IS_METHOD("sign_message")) {
            task_function = sign_message_process;
        } else if (IS_METHOD("sign_tx")) {
            task_function = sign_tx_process;
        } else if (IS_METHOD("sign_liquid_tx")) {
            task_function = sign_liquid_tx_process;
        } else if (IS_METHOD("get_commitments")) {
            task_function = get_commitments_process;
        } else if (IS_METHOD("get_blinding_factor")) {
            task_function = get_blinding_factor_process;
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

        // Call the function
        task_function(&task_process);

        // Then clean up after the process has finished
        cleanup_jade_process(&task_process);
    }
}

// Function to get user confirmation, then wipe all flash memory.
void offer_jade_reset()
{
    // Run 'Reset Jade?'  confirmation screen and wait for yes/no response
    JADE_LOGI("Offering Jade reset");
    const bool bReset = await_yesno_activity(
        "Reset Jade", "Do you want to reset Jade and\nclear all PIN and key data?\nThis action cannot be undone!");

    if (bReset) {
        JADE_LOGI("Yes - requesting numeric confirmation");

        // Force user to confirm a random number
        uint8_t num[PIN_SIZE];
        for (int i = 0; i < PIN_SIZE; ++i) {
            num[i] = get_uniform_random_byte(10);
        }
        char numstr[8];
        format_pin(numstr, sizeof(numstr), num);

        JADE_LOGI("User must enter: %s to reset all data", numstr);

        char confirm_msg[64];
        const int ret = snprintf(confirm_msg, sizeof(confirm_msg), "Confirm value to wipe all data:\n%20s\n", numstr);
        JADE_ASSERT(ret > 0 && ret < sizeof(confirm_msg));

        pin_insert_activity_t* pin_insert;
        make_pin_insert_activity(&pin_insert, "Reset Jade", confirm_msg);
        JADE_ASSERT(sizeof(num) == sizeof(pin_insert->pin));

        gui_set_current_activity(pin_insert->activity);
        run_pin_entry_loop(pin_insert);

        char pinstr[8];
        format_pin(pinstr, sizeof(pinstr), pin_insert->pin);
        JADE_LOGI("User entered: %s", pinstr);

        if (!sodium_memcmp(num, pin_insert->pin, sizeof(num))) {
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
        free(pin_insert);
    }
}

// General settings handler
static inline void update_orientation_text(gui_view_node_t* orientation_textbox)
{
    gui_update_text(orientation_textbox, display_is_orientation_flipped() ? "B" : "A");
}

static void update_idle_timeout_btns(btn_data_t* timeout_btn, const size_t nBtns, uint16_t timeout)
{
    for (int i = 0; i < nBtns; ++i) {
        JADE_ASSERT(timeout_btn[i].btn);
        gui_set_borders(timeout_btn[i].btn, timeout_btn[i].val == timeout ? TFT_BLUE : TFT_BLACK, 2, GUI_BORDER_ALL);
        gui_set_borders_selected_color(timeout_btn[i].btn, TFT_BLOCKSTREAM_GREEN);
        gui_repaint(timeout_btn[i].btn, true);
    }
}

static void handle_settings(jade_process_t* process)
{
    // The idle timeout buttons (1,2,3,5,10,15 mins).
    btn_data_t timeout_btn[] = { { .val = 60, .txt = "1", .btn = NULL }, { .val = 120, .txt = "2", .btn = NULL },
        { .val = 180, .txt = "3", .btn = NULL }, { .val = 300, .txt = "5", .btn = NULL },
        { .val = 600, .txt = "10", .btn = NULL }, { .val = 900, .txt = "15", .btn = NULL } };
    const size_t nBtns = sizeof(timeout_btn) / sizeof(btn_data_t);

    gui_activity_t* act;
    gui_view_node_t* orientation_textbox;
    make_settings_screen(&act, &orientation_textbox, timeout_btn, nBtns);
    JADE_ASSERT(act);
    // update_orientation_text(orientation_textbox);
    update_idle_timeout_btns(timeout_btn, nBtns, storage_get_idle_timeout());

    gui_set_current_activity(act);

    bool loop = true;
    while (loop) {
        int32_t ev_id;
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case BTN_SETTINGS_EXIT:
            loop = false;
            break;

            /*
                    case BTN_SETTINGS_TOGGLE_ORIENTATION:
                        display_toggle_orientation();
                        set_invert_wheel(display_is_orientation_flipped());
                        update_orientation_text(orientation_textbox);
                        gui_set_current_activity(act);  // Causes redraw in new orientation
                        break;
             */
        case BTN_SETTINGS_RESET:
            offer_jade_reset();
            gui_set_current_activity(act);
            break;

        default:
            // Might be an idle-timeout button
            if (ev_id >= BTN_SETTINGS_TIMEOUT_0 && ev_id < BTN_SETTINGS_TIMEOUT_0 + nBtns) {
                const uint32_t idx = ev_id - BTN_SETTINGS_TIMEOUT_0;
                storage_set_idle_timeout(timeout_btn[idx].val);
                update_idle_timeout_btns(timeout_btn, nBtns, timeout_btn[idx].val);
            }
            break;
        }
    }
}

// Sleep/power-down
static void handle_sleep()
{
    const bool bSleep = await_yesno_activity("Sleep", "\nDo you want to put Jade\ninto sleep mode?");
    if (bSleep) {
#ifdef CONFIG_HAS_AXP
        power_shutdown();
#else
        esp_deep_sleep_start();
#endif
    }
}

#ifndef CONFIG_ESP32_NO_BLOBS
// Reset BLE pairing data
static void handle_ble_reset()
{
    const bool bReset = await_yesno_activity("BLE Reset", "\nDo you want to reset all\nbonded devices?");
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

static void handle_ble()
{
    gui_activity_t* act;

    const char* device_name = get_jade_id();
    JADE_ASSERT(device_name);

    gui_view_node_t* ble_status_textbox;
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
static void handle_ble() { await_message_activity("BLE disabled in this firmware"); }
#endif // CONFIG_ESP32_NO_BLOBS

// Device info
static void handle_device()
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

    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_ASSERT(running);

    esp_app_desc_t running_app_info;
    const esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
    JADE_ASSERT(err == ESP_OK);

    gui_activity_t* act;
    make_device_screen(&act, power_status, mac, running_app_info.version);
    JADE_ASSERT(act);
    gui_set_current_activity(act);

    bool loop = true;
    while (loop) {
        int32_t ev_id;
        gui_activity_wait_event(act, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0);

        switch (ev_id) {
        case BTN_INFO_EXIT:
            loop = false;
            break;

#ifdef CONFIG_DEBUG_MODE
        // In debug only, show xpub on screen as qr-code
        case BTN_INFO_SHOW_XPUB: {
            const char* network = storage_get_network_type_restriction() == TEST ? "testnet" : "mainnet";
            char* xpub = NULL;
            if (keychain_get() && wallet_get_xpub(network, NULL, 0, &xpub)) {
                QRCode qrcode;
                Icon qr_icon;

                uint8_t* qrcodeBytes = JADE_CALLOC(qrcode_getBufferSize(4), sizeof(uint8_t));
                const int qret = qrcode_initText(&qrcode, qrcodeBytes, 4, ECC_LOW, xpub);
                JADE_ASSERT(qret == 0);
                qrcode_toIcon(&qrcode, &qr_icon, 3);

                gui_activity_t* xpub_act;
                make_show_xpub(&xpub_act, &qr_icon);
                JADE_ASSERT(xpub_act);
                gui_set_current_activity(xpub_act);
                gui_activity_wait_event(xpub_act, GUI_BUTTON_EVENT, BTN_INFO_EXIT, NULL, NULL, NULL, 0);

                wally_free_string(xpub);
                qrcode_freeIcon(&qr_icon);
                free(qrcodeBytes);
            } else {
                JADE_LOGW("Failed to get root xpub for display");
                await_error_activity("Failed to get root xpub");
            }
            gui_set_current_activity(act);
        }
#endif // CONFIG_DEBUG_MODE

        default:
            break;
        }
    }
}

// Process buttons on the dashboard screen
static void handle_btn(jade_process_t* process, int32_t btn)
{
    switch (btn) {
    case BTN_SLEEP:
        return handle_sleep();
    case BTN_SETTINGS:
        return handle_settings(process);
    case BTN_BLE:
        return handle_ble();
    case BTN_INFO:
        return handle_device();
    default:
        break;
    }
}

// Display the passed dashboard screen
static void display_screen(gui_activity_t* act)
{
    JADE_ASSERT(act);

    // Do not switch to passed activity if already the 'current', as
    // doing so makes the screen flicker and redraw unnecessarily.
    if (gui_current_activity() != act) {
        // Switch to passed screen
        gui_set_current_activity(act);

        // This is the point of return after any gui activities have completed
        // Free everything except for the current activity
        gui_free_noncurrent_activities();

        // Assert all sensitive memory was zero'd
        sensitive_assert_empty();
    }

    // Refeed sensor entropy every time we return to dashboard screen
    const TickType_t tick_count = xTaskGetTickCount();
    refeed_entropy((const unsigned char*)&tick_count, sizeof(tick_count));
}

#ifdef CONFIG_ESP32_NO_BLOBS
static inline bool ble_connected() { return false; }
#endif

// Display the dashboard ready or welcome screen.  Await messages or user GUI input.
static void do_dashboard(jade_process_t* process, const keychain_t* const expected_keychain,
    gui_activity_t* act_dashboard, wait_event_data_t* event_data)
{
    JADE_ASSERT(process);
    JADE_ASSERT(act_dashboard);
    JADE_ASSERT(event_data);

    // Register the button event handler which we check if there are no
    // external messages to handle.
    gui_activity_register_event(act_dashboard, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, sync_wait_event_handler, event_data);

    // Loop all the time the keychain is unchanged, awaiting either a message
    // from companion app or a GUI interaction from the user
    bool acted = true;
    const bool initial_ble = ble_connected();
    const bool initial_usb = usb_connected();
    while (keychain_get() == expected_keychain) {
        // If the last loop did something, ensure the current dashboard screen
        // is displayed. (Doing this too eagerly can either cause unnecessary
        // screen flicker or can cause the dashboard to overwrite other screens
        // eg. BLE pairing/bonding confirm screen.)
        if (acted) {
            display_screen(act_dashboard);
        }

        // 1. Process any message if available (do not block if no message available)
        jade_process_load_in_message(process, false);
        if (process->ctx.cbor) {
            dispatch_message(process);
            acted = true;
            continue;
        }

        // 2. Process any GUI event (again, don't block)
        int32_t ev_id;
        if (sync_wait_event(
                GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, event_data, NULL, &ev_id, NULL, 100 / portTICK_PERIOD_MS)
            == ESP_OK) {
            handle_btn(process, ev_id);
            acted = true;
            continue;
        }

        // Ensure to clear the keychain if ble- or usb- connection status changes.
        // NOTE: if this clears a populated keychain then this loop will complete
        // and cause this function to return.
        if (keychain_get()) {
            if (ble_connected() != initial_ble || usb_connected() != initial_usb) {
                JADE_LOGI("Connection status changed - clearing keychain");
                free_keychain();
            }
        }

        // Looping without having done anything this iteration
        // Set flag to false so we don't set the screen back to dashboard
        acted = false;
    }
}

// Main/default screen/process when ready for user interaction
void dashboard_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    ASSERT_NO_CURRENT_MESSAGE(process);
    JADE_ASSERT(!keychain_get());

    const char* device_name = get_jade_id();
    JADE_ASSERT(device_name);

    wait_event_data_t* const event_data = make_wait_event_data();
    gui_activity_t* act_dashboard = NULL;

    while (true) {
        // Create current 'dashboard' screen, then process all events until that
        // dashboard is no longer appropriate - ie. until the keychain is set (or unset).
        const keychain_t* initial_keychain = keychain_get();
        if (initial_keychain) {
            JADE_LOGI("Logged-in - showing Ready screen");
            make_ready_screen(&act_dashboard, device_name);
        } else if (keychain_has_pin()) {
            JADE_LOGI("Pin set - showing Connect screen");
            make_connect_screen(&act_dashboard, device_name);
        } else {
            JADE_LOGI("No Pin set - showing Setup screen");
            make_setup_screen(&act_dashboard, device_name);
        }

        // This call loops/blocks all the time the user keychain remains unchanged
        // from that passed in.  When it changes we go back round this loop making
        // a new 'dashboard' screen and re-running the dashboard processing loop.
        // NOTE: connecting or disconnecting serial or ble will cause any keys to
        // be cleared (and bzero'd).
        do_dashboard(process, initial_keychain, act_dashboard, event_data);
    }
}
