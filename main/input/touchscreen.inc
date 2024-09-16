#include "gui.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#include <esp_lcd_touch.h>
#include <esp_lcd_touch_ft5x06.h>

static volatile bool shutdown_requested = false;
static volatile bool shutdown_finished = false;

esp_err_t _i2c_init_master(i2c_port_t port_num, int sda_io_num, int scl_io_num, i2c_master_bus_handle_t* handle);
esp_err_t _i2c_deinit(i2c_master_bus_handle_t handle);

static void touchscreen_task(void* ignored)
{
    esp_lcd_touch_handle_t ret_touch = NULL;
    // FIXME: check mirror flags?
    const esp_lcd_touch_config_t tp_cfg = {
        .x_max = CONFIG_DISPLAY_WIDTH + CONFIG_DISPLAY_OFFSET_X,
        .y_max = CONFIG_DISPLAY_HEIGHT + CONFIG_DISPLAY_OFFSET_Y,
        .rst_gpio_num = GPIO_NUM_NC,
        .int_gpio_num = GPIO_NUM_NC,
        .levels = {
            .reset = 0,
            .interrupt = 0,
        },
        .flags = {
            .swap_xy = 0,
            .mirror_x = 0,
            .mirror_y = 0,
        },
    };

    i2c_master_bus_handle_t touch_i2c_handle = NULL;
    ESP_ERROR_CHECK(_i2c_init_master(
        CONFIG_DISPLAY_TOUCHSCREEN_I2C, CONFIG_I2C_TOUCH_SDA, CONFIG_I2C_TOUCH_SCL, &touch_i2c_handle));

    esp_lcd_panel_io_handle_t tp_io_handle = NULL;
    esp_lcd_panel_io_i2c_config_t tp_io_config = ESP_LCD_TOUCH_IO_I2C_FT5x06_CONFIG();
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(CONFIG_DISPLAY_TOUCHSCREEN_I2C, &tp_io_config, &tp_io_handle));
    ESP_ERROR_CHECK(esp_lcd_touch_new_i2c_ft5x06(tp_io_handle, &tp_cfg, &ret_touch));

    uint16_t touch_x[1];
    uint16_t touch_y[1];
    uint16_t touch_strength[1];
    uint8_t touch_cnt = 10;

    // FIXME: don't allow multiple touches within 300 ms?
    // FIXME: this doesn't currently work with Display -> Flip Orientation feature
    // but it could by changing the touch_y[0] > 200 logic with < 40 and inverting prev with next and viceversa
    while (!shutdown_requested) {
        if (esp_lcd_touch_read_data(ret_touch) == ESP_OK) {
            bool touchpad_pressed
                = esp_lcd_touch_get_coordinates(ret_touch, touch_x, touch_y, touch_strength, &touch_cnt, 1);
            if (touchpad_pressed) {
                const uint16_t first_third_end = CONFIG_DISPLAY_WIDTH / 3;
                const uint16_t middle_thirds_end = (CONFIG_DISPLAY_WIDTH * 2) / 3;
                if (touch_y[0] > 200) {
                    if (touch_x[0] <= first_third_end) {
                        gui_prev();
                    } else if (touch_x[0] > first_third_end && touch_x[0] < middle_thirds_end) {
                        gui_front_click();
                    } else if (touch_x[0] >= middle_thirds_end) {
                        gui_next();
                    } else {
                        continue;
                    }
                    vTaskDelay(100 / portTICK_PERIOD_MS);
                }
            }
        }
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }
    ESP_ERROR_CHECK(_i2c_deinit(touch_i2c_handle));
    shutdown_finished = true;
    vTaskDelete(NULL);
}

void touchscreen_init(void)
{
    const BaseType_t retval = xTaskCreatePinnedToCore(
        &touchscreen_task, "touchscreen task", 3 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_PRIMARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create touchscreen task, xTaskCreatePinnedToCore() returned %d", retval);
}

void touchscreen_deinit(void)
{
    shutdown_requested = true;
    while (!shutdown_finished) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    shutdown_requested = false;
    shutdown_finished = false;
}

static void navigation_init(void) { touchscreen_init(); }

static void select_init(void)
{
    // No-op - navigation_init() initialises the touchecreen
}
