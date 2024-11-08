#include "serial.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "process.h"
#include "utils/malloc_ext.h"
#include "wire.h"
#ifdef CONFIG_IDF_TARGET_ESP32
#include <driver/uart.h>
#endif
#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sdkconfig.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef CONFIG_IDF_TARGET_ESP32S3

#ifdef CONFIG_JADE_USE_USB_JTAG_SERIAL

#if !defined(CONFIG_NEWLIB_STDIN_LINE_ENDING_LF) || !defined(CONFIG_NEWLIB_STDOUT_LINE_ENDING_LF)
#error                                                                                                                 \
    "Both CONFIG_NEWLIB_STDIN_LINE_ENDING_LF and CONFIG_NEWLIB_STDOUT_LINE_ENDING_LF must be set for CONFIG_JADE_USE_USB_JTAG_SERIAL mode"
#endif

#if !defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
#error "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG must be set for CONFIG_JADE_USE_USB_JTAG_SERIAL mode"
#endif

#include <esp_vfs.h>

#else
#include <tinyusb.h>
#include <tusb_cdc_acm.h>
#endif
#endif // IDF_TARGET_ESP32S3

static uint8_t* full_serial_data_in = NULL;
static uint8_t* serial_data_out = NULL;

static TaskHandle_t serial_reader_handle = NULL;
static TaskHandle_t* p_serial_writer_handle = NULL;
static volatile bool serial_is_enabled = false;
static SemaphoreHandle_t reader_shutdown_done = NULL;
static SemaphoreHandle_t writer_shutdown_done = NULL;

#ifdef CONFIG_IDF_TARGET_ESP32
// The documentation for 'uart_driver_install()' says:
// "Do not set ESP_INTR_FLAG_IRAM here (the driver’s ISR handler is not located in IRAM)"
// However, we can set the handler to be in IRAM handler in the config, in which case the
// 'uart_driver_install()' code expects it to be set, and issues a warning if not.
// (It actually updates the argument value according to the config.)
// So while we don't *have* to do this, it seems nicer to avoid the warning.
#if CONFIG_UART_ISR_IN_IRAM
#define UART_INTR_ALLOC_FLAGS ESP_INTR_FLAG_IRAM
#else
#define UART_INTR_ALLOC_FLAGS 0
#endif
#endif // IDF_TARGET_ESP32

#ifdef CONFIG_IDF_TARGET_ESP32S3
#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
static TaskHandle_t s_tusb_tskh;

static void tusb_device_task(void* arg)
{
    while (true) {
        tud_task();
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

esp_err_t tusb_run_task(void)
{
    assert(!s_tusb_tskh);
    void* task_arg = NULL;
    xTaskCreatePinnedToCore(tusb_device_task, "TinyUSB", 1024 * 4, task_arg, 5, &s_tusb_tskh, 1);
    if (!s_tusb_tskh) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t tusb_stop_task(void)
{
    assert(s_tusb_tskh);
    vTaskDelete(s_tusb_tskh);
    s_tusb_tskh = NULL;
    return ESP_OK;
}
#endif
#endif // IDF_TARGET_ESP32S3

static void post_exit_event_and_await_death(SemaphoreHandle_t* semaphore_done)
{
    // Post 'exit' event
    xSemaphoreGive(*semaphore_done);
    // wait to be killed
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

static void serial_reader(void* ignore)
{
    uint8_t* const serial_data_in = full_serial_data_in + 1;
    size_t read = 0;
    TickType_t last_processing_time = 0;

    while (true) {
        if (!serial_is_enabled) {
            break;
        }

        const size_t maxrecv = MAX_INPUT_MSG_SIZE - read;

#ifdef CONFIG_IDF_TARGET_ESP32
        // Read incoming data max to fill buffer
        const int len = uart_read_bytes(UART_NUM_0, serial_data_in + read, maxrecv, 20 / portTICK_PERIOD_MS);

        if (len < 0) {
            // Pause and retry... can we do anything else here ?
            JADE_LOGE("Error reading bytes from serial device: %u", len);
            vTaskDelay(50 / portTICK_PERIOD_MS);
            continue;
        }

        // If no data received, short sleep (to allow other tasks to run) and loop
        if (!len) {
            vTaskDelay(20 / portTICK_PERIOD_MS);
            continue;
        }
#endif // IDF_TARGET_ESP32

#ifdef CONFIG_IDF_TARGET_ESP32S3

#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
        ulTaskNotifyTake(pdTRUE, 100 / portTICK_PERIOD_MS);

        const size_t nrecv = maxrecv < CONFIG_TINYUSB_CDC_RX_BUFSIZE ? maxrecv : CONFIG_TINYUSB_CDC_RX_BUFSIZE;
        size_t len = 0;
        const esp_err_t ret = tinyusb_cdcacm_read(TINYUSB_CDC_ACM_0, serial_data_in + read, nrecv, &len);
        if (ret != ESP_OK) {
            JADE_LOGE("Error reading bytes from serial device: %u", ret);
            continue;
        }

#else
        // Need a short delay to allow other tasks to run
        vTaskDelay(10 / portTICK_PERIOD_MS);
        const size_t len = fread(serial_data_in + read, 1, maxrecv, stdin);
#endif
        if (!len) {
            // No data to receive/timeout
            continue;
        }
#endif // CONFIG_IDF_TARGET_ESP32S3

        JADE_LOGD("Passing %u+%u bytes from serial device to common handler", read, len);
        const bool force_reject_if_no_msg = false;
        handle_data(full_serial_data_in, &read, len, &last_processing_time, force_reject_if_no_msg, serial_data_out);
    }
    post_exit_event_and_await_death(&reader_shutdown_done);
}

#ifdef CONFIG_IDF_TARGET_ESP32S3
#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
static void tinyusb_cdc_rx_callback(int itf, cdcacm_event_t* event)
{
    /* It is important we don't do heavy work in this cb because it is called
     * in the context of an interrupt handler, hence we notify serial_data_handler
     * that is time to read some data */
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(serial_reader_handle, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}
#endif
#endif // IDF_TARGET_ESP32S3

static bool write_serial(const uint8_t* msg, const size_t length, void* ignore)
{
    JADE_ASSERT(msg);
    JADE_ASSERT(length);

    int written = 0;
    while (written != length) {
#ifdef CONFIG_IDF_TARGET_ESP32S3
#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
        const int wrote = tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, msg + written, length - written);
#else
        const int wrote = fwrite(msg + written, 1, length - written, stdout);
#endif
#endif

#ifdef CONFIG_IDF_TARGET_ESP32
        const int wrote = uart_write_bytes(UART_NUM_0, msg + written, length - written);
#endif
        if (wrote == -1) {
            return false;
        }
        written += wrote;
    }
    return true;
}

static void serial_writer(void* ignore)
{
    while (true) {
        if (!serial_is_enabled) {
            break;
        }
        vTaskDelay(20 / portTICK_PERIOD_MS);
        while (jade_process_get_out_message(&write_serial, SOURCE_SERIAL, NULL)) {
            // process messages
        }
#ifdef CONFIG_IDF_TARGET_ESP32S3
#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
        /* if flush fails we ignore it */
        tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, 0);
#else
        fflush(stdout);
        /* it is necessary to wait a little for fflush to have an effect before
         * fsync has all the data */
        vTaskDelay(10 / portTICK_PERIOD_MS);
        fsync(fileno(stdout));
#endif
#endif
        xTaskNotifyWait(0x00, ULONG_MAX, NULL, 100 / portTICK_PERIOD_MS);
    }
    post_exit_event_and_await_death(&writer_shutdown_done);
}

static bool serial_init_internal(void)
{
    uint32_t reader_stack_size = 5 * 1024;
#ifdef CONFIG_IDF_TARGET_ESP32S3
#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
    tinyusb_config_t partial_init = { 0 };
    esp_err_t err = tinyusb_driver_install(&partial_init);
    if (err != ESP_OK) {
        return false;
    }
    err = tusb_run_task();
    if (err != ESP_OK) {
        return false;
    }
    const tinyusb_config_cdcacm_t acm_cfg = { .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 64,
        .callback_rx = tinyusb_cdc_rx_callback,
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL };
    err = tusb_cdc_acm_init(&acm_cfg);
    if (err != ESP_OK) {
        return false;
    }
    reader_stack_size = 8 * 1024;
#endif
#endif // IDF_TARGET_ESP32S3

#ifdef CONFIG_IDF_TARGET_ESP32
    const uart_config_t uart_config = { .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_DEFAULT };

    esp_err_t err = uart_param_config(UART_NUM_0, &uart_config);
    if (err != ESP_OK) {
        return false;
    }

    /* maximum OTA CHUNK + cbor overhead for RX */
    err = uart_driver_install(UART_NUM_0, (1024 * 4) + 46, 1024, 0, NULL, UART_INTR_ALLOC_FLAGS);
    if (err != ESP_OK) {
        return false;
    }
#endif // IDF_TARGET_ESP32

    // The tasks run while this flag is set
    serial_is_enabled = true;

    BaseType_t retval = xTaskCreatePinnedToCore(&serial_reader, "serial_reader", reader_stack_size, NULL,
        JADE_TASK_PRIO_READER, &serial_reader_handle, JADE_CORE_SECONDARY);

    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create serial_reader task, xTaskCreatePinnedToCore() returned %d", retval);

    retval = xTaskCreatePinnedToCore(&serial_writer, "serial_writer", 4 * 1024, NULL, JADE_TASK_PRIO_WRITER,
        p_serial_writer_handle, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create serial_writer task, xTaskCreatePinnedToCore() returned %d", retval);

    return true;
}

bool serial_init(TaskHandle_t* serial_handle)
{
    JADE_ASSERT(serial_handle);
    JADE_ASSERT(!full_serial_data_in);
    JADE_ASSERT(!serial_data_out);
    JADE_ASSERT(!serial_is_enabled);
    JADE_ASSERT(!reader_shutdown_done);
    JADE_ASSERT(!writer_shutdown_done);
    reader_shutdown_done = xSemaphoreCreateBinary();
    writer_shutdown_done = xSemaphoreCreateBinary();
    JADE_ASSERT(reader_shutdown_done);
    JADE_ASSERT(writer_shutdown_done);

    // Extra byte at the start for source-id
    full_serial_data_in = JADE_MALLOC_PREFER_SPIRAM(MAX_INPUT_MSG_SIZE + 1);
    full_serial_data_in[0] = SOURCE_SERIAL;
    serial_data_out = JADE_MALLOC_PREFER_SPIRAM(MAX_OUTPUT_MSG_SIZE);
    p_serial_writer_handle = serial_handle;
    return serial_init_internal();
}

bool serial_enabled(void) { return serial_is_enabled; }

void serial_start(void)
{
    if (serial_is_enabled) {
        return;
    }
    serial_init_internal();
}

void serial_stop(void)
{
    if (!serial_is_enabled) {
        return;
    }

    // flag tasks to die
    serial_is_enabled = false;

    xSemaphoreTake(reader_shutdown_done, portMAX_DELAY);
    vTaskDelete(serial_reader_handle);

    xSemaphoreTake(writer_shutdown_done, portMAX_DELAY);
    vTaskDelete(*p_serial_writer_handle);

#ifdef CONFIG_IDF_TARGET_ESP32
    const esp_err_t err = uart_driver_delete(UART_NUM_0);
    JADE_ASSERT(err == ESP_OK);
#endif

#ifdef CONFIG_IDF_TARGET_ESP32S3
#ifndef CONFIG_JADE_USE_USB_JTAG_SERIAL
    esp_err_t err = tusb_cdc_acm_deinit(TINYUSB_CDC_ACM_0);
    JADE_ASSERT(err == ESP_OK);
    err = tusb_stop_task();
    JADE_ASSERT(err == ESP_OK);
    err = tinyusb_driver_uninstall();
    JADE_ASSERT(err == ESP_OK);
#endif
#endif
}
