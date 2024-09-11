#include <esp_chip_info.h>
#include <esp_efuse.h>
#include <esp_event.h>
#include <esp_mac.h>
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
#include "utils/wally_ext.h"
#include <sdkconfig.h>

#include "camera.h"
#include "jade_assert.h"
#include "process.h"
#include "process/process_utils.h"
#include "random.h"
#ifdef CONFIG_IDF_TARGET_ESP32S3
#include "usbhmsc/usbhmsc.h"
#endif
#include "sensitive.h"
#include "serial.h"
#ifdef CONFIG_ETH_USE_OPENETH
#ifdef CONFIG_HAS_CAMERA
#include "qemu_display.h"
#endif
#include "qemu_tcp.h"
#endif

#ifdef CONFIG_BT_ENABLED
#include "ble/ble.h"
#endif

#include "idletimer.h"
#include "power.h"
#include "smoketest.h"
#include "storage.h"
#include "wallet.h"

// Running partition/fw info & chip info, fetched once at boot
esp_app_desc_t running_app_info;
esp_chip_info_t chip_info;
uint8_t macid[6];

#ifndef CONFIG_LOG_DEFAULT_LEVEL_NONE
int serial_logger(const char* message, va_list fmt);
#endif

void offer_startup_options(void);
void dashboard_process(void* process_ptr);
void temp_stack_init(void);

// CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS is an insecure flag which atm we only expect to be
// set for JADEv2 in order to support initialising the attestation functionality with secure-boot
// enabled.  The provisioning process means this setup is made secure before leaving the factory.
// To enable attestation with secure-boot in a diy scenario this check must be skipped, but it is
// incumbent on the diy-developer to ensure the attestation initialisation is run successfully to
// completion (after the first boot) and the hw unit made secure before it is used.
// (The unit cannot be considered secure until esp_efuse_write_field_bit(ESP_EFUSE_WR_DIS_RD_DIS) has
// been called, once all the read-protected efuse keys have been programmed.  [This prevents marking
// any further efuses as un-readable.])
// See: https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32s3/security/secure-boot-v2.html
//  #restrictions-after-secure-boot-is-enabled
#if defined(CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS) && !defined(CONFIG_BOARD_TYPE_JADE_V2)
#error "Error, insecure flag CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS set"
#endif

static void ensure_boot_flags(void)
{
#ifdef CONFIG_SECURE_BOOT
    esp_efuse_disable_basic_rom_console();
    esp_efuse_disable_rom_download_mode();
#endif
}

static void validate_running_image(void)
{
    // Populate chip info struct and mac-id
    esp_chip_info(&chip_info);
    esp_efuse_mac_get_default(macid);

    // Check running partition/fw image
    const esp_partition_t* running = esp_ota_get_running_partition();
    JADE_LOGI("Running partition ptr: %p", running);

    if (!running) {
        JADE_LOGE("Cannot get running partition - cannot validate");
        return;
    }

    // Populate the running partition info struct
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

#if defined(CONFIG_HAS_CAMERA) && !defined(CONFIG_ETH_USE_OPENETH)
static bool rnd_camera_feed(
    const size_t width, const size_t height, const uint8_t* data, const size_t len, void* ctx_data)
{
    JADE_ASSERT(data);
    JADE_ASSERT(len);
    JADE_ASSERT(ctx_data);
    size_t* counter = (size_t*)ctx_data;
    refeed_entropy(data, len);
    return ++*counter > 10;
}
#endif // CONFIG_HAS_CAMERA && !CONFIG_ETH_USE_OPENETH

static void boot_process(void)
{
    TaskHandle_t* serial_handle = NULL;
    TaskHandle_t* ble_handle = NULL;
    TaskHandle_t* qemu_tcp_handle = NULL;
    TaskHandle_t* gui_handle = NULL;

    if (!jade_process_init(&serial_handle, &ble_handle, &qemu_tcp_handle, &gui_handle)) {
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

    keychain_init_cache();
    display_init(gui_handle);
    gui_init(gui_handle);

    // Display splash screen with Blockstream logo.  Carry out further initialisation
    // while that screen is shown for a short time.  Then test to see whether the
    // user clicked the front button.  If they did, we offer to reset the jade
    // (one-time passkey required).
    JADE_LOGI("Showing splash screen");
    gui_activity_t* const splash = gui_display_splash();
    vTaskDelay(100 / portTICK_PERIOD_MS);

    // Idletimer init decides whether to power the screen or not based on whether this
    // is a soft restart due to inactivity.
    // NOTE: input methods use idle-timer, so are dependent.
    idletimer_init();

#if !defined(CONFIG_ETH_USE_OPENETH) && !defined(CONFIG_DISPLAY_TOUCHSCREEN)
    input_init();
    button_init();
    wheel_init();
#endif

#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
    touchscreen_init();
#endif

    wait_event_data_t* const event_data = gui_activity_make_wait_event_data(splash); // activity takes ownership
    JADE_ASSERT(event_data);
    gui_activity_register_event(splash, GUI_EVENT, GUI_FRONT_CLICK_EVENT, sync_wait_event_handler, event_data);

#ifdef CONFIG_IDF_TARGET_ESP32S3
    usbstorage_init();
#endif

    if (!serial_init(serial_handle)) {
        JADE_ABORT();
    }

#ifdef CONFIG_ETH_USE_OPENETH
    if (!qemu_tcp_init(qemu_tcp_handle)) {
        JADE_LOGI("Failed to start qemu tcp handler");
        JADE_ABORT();
    }
#ifdef CONFIG_HAS_CAMERA
    if (!qemu_start_display_webserver()) {
        JADE_LOGI("Failed to start qemu web display");
        JADE_ABORT();
    }
#endif
#endif

    sensitive_init();
    temp_stack_init();

    // We spend a bit of time initialising random while the splash screen is being shown
    random_full_initialization();

#if defined(CONFIG_HAS_CAMERA) && !defined(CONFIG_ETH_USE_OPENETH)
    size_t counter = 0;
    jade_camera_process_images(&rnd_camera_feed, &counter, false, false, NULL, QR_GUIDES_NONE, NULL, NULL);
#endif

    jade_wally_init();
    wallet_init();

    if (!keychain_init_unit_key()) {
        JADE_ABORT();
    }

#ifdef CONFIG_BT_ENABLED
    // Delay BLE initialisation as uses the hw unit key which is not initialised until
    // the first run of keychain_init() (on a new or factory-reset unit).
    // Should not really cause an issue as on a fresh unit BLE should be disabled anyway,
    // but better to be safe than sorry.
    if (!ble_init(ble_handle)) {
        JADE_ABORT();
    }
#endif

    // Check if the user had clicked.
    int32_t ev_id;
    const esp_err_t esp_ret = sync_wait_event(event_data, NULL, &ev_id, NULL, 100 / portTICK_PERIOD_MS);

    // If clicked, offer startup/advanced menu
    if (esp_ret == ESP_OK && ev_id == GUI_FRONT_CLICK_EVENT) {
        JADE_LOGI("User clicked on splash screen - showing startup/advanced options");
        offer_startup_options();
    }
}

#ifndef CONFIG_JADE_QA
static void start_dashboard(void)
{
    JADE_LOGI("Starting dashboard on core %u, with priority %u", xPortGetCoreID(), uxTaskPriorityGet(NULL));

    // Hand over to the main dashboard task
    jade_process_t main_process;
    init_jade_process(&main_process);

    // runs forever (on default core 0)
    dashboard_process(&main_process);
}
#endif

void app_main(void)
{
    ensure_boot_flags();
    random_start_collecting();
    validate_running_image();
    boot_process();
    sensitive_assert_empty();
#ifndef CONFIG_JADE_QA
    start_dashboard();
#else
    start_smoketest();
#endif
}
