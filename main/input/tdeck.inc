#include "gui.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#include "button_gpio.h"
#include "iot_button.h"

#include <driver/gpio.h>
#include <driver/i2c_master.h>
#include <esp_timer.h>

#define BOARD_POWERON_GPIO  10
#define KB_I2C_ADDR         0x55
#define KB_I2C_TIMEOUT_MS   50

// Keyboard controller command: set backlight brightness (0-255, 0 = off)
#define KB_BRIGHTNESS_CMD   0x01

#define TB_LEFT_GPIO        1
#define TB_RIGHT_GPIO       2
#define TB_UP_GPIO          3
#define TB_DOWN_GPIO        15
#define TB_PRESS_GPIO       0

// Ignore edges arriving faster than this - filters contact noise and
// caps the overall scroll rate
#define TB_DEBOUNCE_US      2000

// Edges required per scroll step - raise to reduce sensitivity
#define TB_EDGES_PER_EVENT  2

// Edges further apart than this do not accumulate towards a step
#define TB_GESTURE_TIMEOUT_US 300000

// Pending keyboard backlight level (0-255), or -1 when no change pending.
// Set from other tasks (eg. the screen backlight code) - applied by the
// keyboard task below, which owns the i2c device.
static volatile int16_t kb_backlight_req = -1;

void tdeck_set_keyboard_backlight(const uint8_t value) { kb_backlight_req = value; }

static void tdeck_keyboard_task(void* unused)
{
    gpio_set_direction(BOARD_POWERON_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(BOARD_POWERON_GPIO, 1);

    vTaskDelay(500 / portTICK_PERIOD_MS);

    i2c_master_bus_config_t bus_config = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = CONFIG_I2C_SDA,
        .scl_io_num = CONFIG_I2C_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t kb_i2c_bus;
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_config, &kb_i2c_bus));

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = KB_I2C_ADDR,
        .scl_speed_hz = CONFIG_I2C_MASTER_CLK,
    };
    i2c_master_dev_handle_t kb_i2c_dev;
    ESP_ERROR_CHECK(i2c_master_bus_add_device(kb_i2c_bus, &dev_cfg, &kb_i2c_dev));

    for (;;) {
        // Apply any pending keyboard backlight change (retried on failure)
        const int16_t kb_bl = kb_backlight_req;
        if (kb_bl >= 0) {
            const uint8_t cmd[] = { KB_BRIGHTNESS_CMD, (uint8_t)kb_bl };
            if (i2c_master_transmit(kb_i2c_dev, cmd, sizeof(cmd), KB_I2C_TIMEOUT_MS) == ESP_OK) {
                kb_backlight_req = -1;
            }
        }

        uint8_t key_byte = 0;
        const esp_err_t ret = i2c_master_receive(kb_i2c_dev, &key_byte, 1, KB_I2C_TIMEOUT_MS);
        if (ret == ESP_OK && key_byte != 0) {
            JADE_LOGD("keyboard key 0x%02x", key_byte);
            if (key_byte == 0x0D) {
                esp_event_post(GUI_BUTTON_EVENT, BTN_KEYBOARD_ENTER, NULL, 0, portMAX_DELAY);
            } else if (key_byte == 0x08) {
                esp_event_post(GUI_BUTTON_EVENT, BTN_KEYBOARD_BACKSPACE, NULL, 0, portMAX_DELAY);
            } else if (key_byte >= 32 && key_byte < 128) {
                esp_event_post(GUI_BUTTON_EVENT, BTN_KEYBOARD_ASCII_OFFSET + key_byte, NULL, 0, portMAX_DELAY);
            }
        }
        vTaskDelay(30 / portTICK_PERIOD_MS);
    }

    vTaskDelete(NULL);
}

static void tb_press_trigger(void* arg, void* ctx) { gui_front_click(); }

// The trackball direction outputs are not buttons - each line toggles
// level once per step of ball travel, so treat every edge as one scroll
// increment (the resting level of a line is arbitrary).
typedef enum { TB_NAV_PREV, TB_NAV_NEXT } tb_nav_t;

static QueueHandle_t tb_queue = NULL;

static void tb_isr(void* arg)
{
    static int64_t last_event_us = 0;
    static tb_nav_t last_nav = TB_NAV_PREV;
    static uint8_t edge_count = 0;

    const int64_t now = esp_timer_get_time();
    const int64_t elapsed = now - last_event_us;
    if (elapsed < TB_DEBOUNCE_US) {
        return;
    }
    last_event_us = now;

    const tb_nav_t nav = (tb_nav_t)(uintptr_t)arg;
    if (nav != last_nav || elapsed > TB_GESTURE_TIMEOUT_US) {
        last_nav = nav;
        edge_count = 0;
    }
    if (++edge_count < TB_EDGES_PER_EVENT) {
        return;
    }
    edge_count = 0;

    BaseType_t higher_priority_woken = pdFALSE;
    xQueueSendFromISR(tb_queue, &nav, &higher_priority_woken);
    if (higher_priority_woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static void tdeck_trackball_task(void* unused)
{
    for (;;) {
        tb_nav_t nav;
        if (xQueueReceive(tb_queue, &nav, portMAX_DELAY) == pdTRUE) {
            if (nav == TB_NAV_PREV) {
                gui_prev();
            } else {
                gui_next();
            }
        }
    }
}

void navigation_init(void)
{
    BaseType_t retval = xTaskCreatePinnedToCore(
        &tdeck_keyboard_task, "tdeck_kbd", 3 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create tdeck_keyboard task, xTaskCreatePinnedToCore() returned %d",
        retval);

    tb_queue = xQueueCreate(8, sizeof(tb_nav_t));
    JADE_ASSERT(tb_queue);

    retval = xTaskCreatePinnedToCore(
        &tdeck_trackball_task, "tdeck_tball", 2 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create tdeck_trackball task, xTaskCreatePinnedToCore() returned %d",
        retval);

    const gpio_config_t tb_cfg = {
        .pin_bit_mask = (1ULL << TB_LEFT_GPIO) | (1ULL << TB_RIGHT_GPIO) | (1ULL << TB_UP_GPIO)
            | (1ULL << TB_DOWN_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .intr_type = GPIO_INTR_ANYEDGE,
    };
    ESP_ERROR_CHECK(gpio_config(&tb_cfg));

    const esp_err_t rc = gpio_install_isr_service(0);
    JADE_ASSERT(rc == ESP_OK || rc == ESP_ERR_INVALID_STATE);
    ESP_ERROR_CHECK(gpio_isr_handler_add(TB_LEFT_GPIO, tb_isr, (void*)(uintptr_t)TB_NAV_PREV));
    ESP_ERROR_CHECK(gpio_isr_handler_add(TB_UP_GPIO, tb_isr, (void*)(uintptr_t)TB_NAV_PREV));
    ESP_ERROR_CHECK(gpio_isr_handler_add(TB_RIGHT_GPIO, tb_isr, (void*)(uintptr_t)TB_NAV_NEXT));
    ESP_ERROR_CHECK(gpio_isr_handler_add(TB_DOWN_GPIO, tb_isr, (void*)(uintptr_t)TB_NAV_NEXT));

    const button_config_t btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    button_handle_t btn_press = NULL;
    const button_gpio_config_t press_gpio_cfg = { .gpio_num = TB_PRESS_GPIO, .active_level = 0 };
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&btn_cfg, &press_gpio_cfg, &btn_press));
    JADE_ASSERT(btn_press);
    ESP_ERROR_CHECK(iot_button_register_cb(btn_press, BUTTON_PRESS_UP, NULL, tb_press_trigger, NULL));
}

void select_init(void)
{
}
