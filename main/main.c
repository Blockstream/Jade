#include <esp_event.h>
#include <esp_ota_ops.h>

#include <driver/gpio.h>
#include <driver/spi_master.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdio.h>
#include <string.h>

#include "button_events.h"
#include "display.h"
#include "gui.h"
#include "input.h"
#include "keychain.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"
#include <sdkconfig.h>

#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "process.h"
#include "process/process_utils.h"
#include "random.h"
#include "sensitive.h"
#include "serial.h"
#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
#include "qemu_tcp.h"
#endif

#ifndef CONFIG_ESP32_NO_BLOBS
#include "ble/ble.h"
#endif

#include "idletimer.h"
#include "power.h"
#include "storage.h"
#include "wallet.h"

#ifndef CONFIG_LOG_DEFAULT_LEVEL_NONE
int serial_logger(const char* message, va_list fmt);
#endif

void offer_startup_options(void);
void dashboard_process(void* process_ptr);

static void crypto_init(void)
{
    JADE_WALLY_VERIFY(wally_init(0));
    unsigned char ctx_rnd[WALLY_SECP_RANDOMIZE_LEN];
    SENSITIVE_PUSH(ctx_rnd, sizeof(ctx_rnd));
    get_random(ctx_rnd, WALLY_SECP_RANDOMIZE_LEN);

    JADE_WALLY_VERIFY(wally_secp_randomize(ctx_rnd, WALLY_SECP_RANDOMIZE_LEN));
    SENSITIVE_POP(ctx_rnd);
}

static void boot_process(void)
{
    TaskHandle_t* serial_handle = NULL;
    TaskHandle_t* ble_handle = NULL;
    TaskHandle_t* qemu_tcp_handle = NULL;

    if (!jade_process_init(&serial_handle, &ble_handle, &qemu_tcp_handle)) {
        JADE_ABORT();
    }

#ifndef CONFIG_LOG_DEFAULT_LEVEL_NONE
    esp_log_set_vprintf(serial_logger);
#endif

    const esp_err_t rc = power_init();
    JADE_ASSERT(rc == ESP_OK);

    if (!storage_init()) {
        JADE_ABORT();
    }

    wallet_init();
    display_init();
    gui_init();
    idletimer_init();
    input_init();
    button_init();
    wheel_init();

    // Display splash screen with Blockstream logo.  Carry out further initialisation
    // while that screen is shown for a short time.  Then test to see whether the
    // user clicked the front button.  If they did, we offer to reset the jade
    // (one-time passkey required).
    JADE_LOGI("Showing splash screen");
    gui_activity_t* act = display_splash();
    JADE_ASSERT(act);
    wait_event_data_t* event_data = make_wait_event_data();
    JADE_ASSERT(event_data);
    gui_activity_register_event(act, GUI_EVENT, GUI_FRONT_CLICK_EVENT, sync_wait_event_handler, event_data);

    if (!serial_init(serial_handle)) {
        JADE_ABORT();
    }

#if defined(CONFIG_FREERTOS_UNICORE) && defined(CONFIG_ETH_USE_OPENETH)
    if (!qemu_tcp_init(qemu_tcp_handle)) {
        JADE_LOGI("Failed to start qemu tcp handler");
        JADE_ABORT();
    }
#endif

#ifndef CONFIG_ESP32_NO_BLOBS
    if (!ble_init(ble_handle)) {
        JADE_ABORT();
    }
#endif

    sensitive_init();

    // We spend a bit of time initialising random while the splash screen is being shown
    random_full_initialization();
    crypto_init();

    if (!keychain_init()) {
        JADE_ABORT();
    }

    // Check if the user had clicked.
    int32_t ev_id;
    const esp_err_t esp_ret
        = sync_wait_event(GUI_EVENT, GUI_FRONT_CLICK_EVENT, event_data, NULL, &ev_id, NULL, 100 / portTICK_PERIOD_MS);

    free_wait_event_data(event_data);

    // Return whether the user clicked the front btn
    const bool clicked = esp_ret == ESP_OK && ev_id == GUI_FRONT_CLICK_EVENT;

    // If clicked, offer startup/advanced menu
    if (clicked) {
        JADE_LOGI("User clicked on splash screen - showing startup/advanced options");
        offer_startup_options();
    }
}

static void start_dashboard(void)
{
    JADE_LOGI("Starting dashboard on core %u", xPortGetCoreID());

    // Hand over to the main dashboard task
    jade_process_t main_process;
    init_jade_process(&main_process);

    // runs forever (on default core 0)
    dashboard_process(&main_process);
}

static void validate_running_image(void)
{
    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_LOGI("Running partition ptr: %p", running);

    if (!running) {
        JADE_LOGE("Cannot get running partition - cannot validate");
        return;
    }

    esp_app_desc_t running_app_info;
    esp_err_t err = esp_ota_get_partition_description(running, &running_app_info);
    if (err == ESP_OK) {
        JADE_LOGI("Running firmware version: %s", running_app_info.version);
    } else {
        JADE_LOGE("esp_ota_get_partition_description(%p) returned %d", running, err);
    }

    esp_ota_img_states_t ota_state;
    err = esp_ota_get_state_partition(running, &ota_state);
    if (err != ESP_OK) {
        JADE_LOGE("esp_ota_get_state_partition(%p) returned %d", running, err);
        return;
    }

    JADE_LOGI("Running partition state: %d", ota_state);
    if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
        JADE_LOGI("First boot of current version");

        err = esp_ota_mark_app_valid_cancel_rollback();
        if (err == ESP_OK) {
            JADE_LOGI("Successfully marked current partition as good");
        } else {
            JADE_LOGE("esp_ota_mark_app_valid_cancel_rollback() returned %d", err);
        }
    }
}

void app_main(void)
{
    random_start_collecting();
    boot_process();
    sensitive_assert_empty();
    validate_running_image();
    start_dashboard();
}
