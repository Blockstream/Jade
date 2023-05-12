#include "serial.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "process.h"
#include "utils/malloc_ext.h"
#include "wire.h"

#include <driver/uart.h>
#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sdkconfig.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t* full_serial_data_in = NULL;
static uint8_t* serial_data_out = NULL;

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

static void serial_reader(void* ignore)
{
    uint8_t* const serial_data_in = full_serial_data_in + 1;
    size_t read = 0;
    TickType_t last_processing_time = 0;

    while (1) {
        // Read incoming data max to fill buffer
        const int len
            = uart_read_bytes(UART_NUM_0, serial_data_in + read, MAX_INPUT_MSG_SIZE - read, 20 / portTICK_PERIOD_MS);

        if (len < 0) {
            // Pause and retry... can we do anything else here ?
            JADE_LOGE("Error reading bytes from serial device: %u", len);
            vTaskDelay(50 / portTICK_PERIOD_MS);
            continue;
        }

        // If no data received, short sleep and loop.
        // NOTE: we only call handle_data() when the next data arrives - this
        // is to be consistent with 'notification-based' processing (eg. BLE).
        if (len == 0) {
            vTaskDelay(20 / portTICK_PERIOD_MS);
            continue;
        }

        // Pass to common handler
        JADE_LOGD("Passing %u+%u bytes from serial device to common handler", read, len);
        const bool force_reject_if_no_msg = false;
        handle_data(full_serial_data_in, &read, len, &last_processing_time, force_reject_if_no_msg, serial_data_out);
    }
}

static bool write_serial(const uint8_t* msg, const size_t length, void* ignore)
{
    JADE_ASSERT(msg);
    JADE_ASSERT(length);

    int written = 0;
    while (written != length) {
        const int wrote = uart_write_bytes(UART_NUM_0, msg + written, length - written);
        if (wrote == -1) {
            return false;
        }
        written += wrote;
    }
    return true;
}

static void serial_writer(void* ignore)
{
    while (1) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
        while (jade_process_get_out_message(&write_serial, SOURCE_SERIAL, NULL)) {
            // process messages
        }
        xTaskNotifyWait(0x00, ULONG_MAX, NULL, portMAX_DELAY);
    }
}

bool serial_init(TaskHandle_t* serial_handle)
{
    JADE_ASSERT(serial_handle);
    JADE_ASSERT(!full_serial_data_in);
    JADE_ASSERT(!serial_data_out);

    const uart_config_t uart_config = { .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_DEFAULT };

    // Extra byte at the start for source-id
    full_serial_data_in = JADE_MALLOC_PREFER_SPIRAM(MAX_INPUT_MSG_SIZE + 1);
    full_serial_data_in[0] = SOURCE_SERIAL;
    serial_data_out = JADE_MALLOC_PREFER_SPIRAM(MAX_OUTPUT_MSG_SIZE);

    esp_err_t err = uart_param_config(UART_NUM_0, &uart_config);
    if (err != ESP_OK) {
        return false;
    }

    /* maximum OTA CHUNK + cbor overhead for RX */
    err = uart_driver_install(UART_NUM_0, (1024 * 4) + 46, 1024, 0, NULL, UART_INTR_ALLOC_FLAGS);
    if (err != ESP_OK) {
        return false;
    }

    BaseType_t retval = xTaskCreatePinnedToCore(
        &serial_reader, "serial_reader", 5 * 1024, NULL, JADE_TASK_PRIO_READER, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create serial_reader task, xTaskCreatePinnedToCore() returned %d", retval);

    retval = xTaskCreatePinnedToCore(
        &serial_writer, "serial_writer", 2 * 1024, NULL, JADE_TASK_PRIO_WRITER, serial_handle, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create serial_writer task, xTaskCreatePinnedToCore() returned %d", retval);

    return true;
}
