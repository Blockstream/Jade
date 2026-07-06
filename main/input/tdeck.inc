#include "gui.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#include "button_gpio.h"
#include "iot_button.h"

#include <driver/gpio.h>
#include <driver/i2c_master.h>

#define BOARD_POWERON_GPIO  10
#define KB_I2C_ADDR         0x55
#define KB_I2C_TIMEOUT_MS   50

#define TB_LEFT_GPIO        1
#define TB_RIGHT_GPIO       2
#define TB_PRESS_GPIO       0

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
        uint8_t key_byte = 0;
        const esp_err_t ret = i2c_master_receive(kb_i2c_dev, &key_byte, 1, KB_I2C_TIMEOUT_MS);
        if (ret == ESP_OK && key_byte != 0) {
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

static void tb_left_trigger(void* arg, void* ctx) { gui_prev(); }
static void tb_right_trigger(void* arg, void* ctx) { gui_next(); }
static void tb_press_trigger(void* arg, void* ctx) { gui_front_click(); }

void navigation_init(void)
{
    BaseType_t retval = xTaskCreatePinnedToCore(
        &tdeck_keyboard_task, "tdeck_kbd", 3 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create tdeck_keyboard task, xTaskCreatePinnedToCore() returned %d",
        retval);

    const button_config_t btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    button_handle_t btn_left = NULL;
    const button_gpio_config_t left_gpio_cfg = { .gpio_num = TB_LEFT_GPIO, .active_level = 0 };
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&btn_cfg, &left_gpio_cfg, &btn_left));
    JADE_ASSERT(btn_left);
    ESP_ERROR_CHECK(iot_button_register_cb(btn_left, BUTTON_PRESS_DOWN, NULL, tb_left_trigger, NULL));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_left, BUTTON_LONG_PRESS_HOLD, NULL, tb_left_trigger, NULL));

    button_handle_t btn_right = NULL;
    const button_gpio_config_t right_gpio_cfg = { .gpio_num = TB_RIGHT_GPIO, .active_level = 0 };
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&btn_cfg, &right_gpio_cfg, &btn_right));
    JADE_ASSERT(btn_right);
    ESP_ERROR_CHECK(iot_button_register_cb(btn_right, BUTTON_PRESS_DOWN, NULL, tb_right_trigger, NULL));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_right, BUTTON_LONG_PRESS_HOLD, NULL, tb_right_trigger, NULL));

    button_handle_t btn_press = NULL;
    const button_gpio_config_t press_gpio_cfg = { .gpio_num = TB_PRESS_GPIO, .active_level = 0 };
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&btn_cfg, &press_gpio_cfg, &btn_press));
    JADE_ASSERT(btn_press);
    ESP_ERROR_CHECK(iot_button_register_cb(btn_press, BUTTON_PRESS_UP, NULL, tb_press_trigger, NULL));
}

void select_init(void)
{
}
