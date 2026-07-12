#include "gui.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#if defined(CONFIG_BOARD_TYPE_WS_TOUCH_LCD2)
// No PMU, so relevant power files will not have been included
#include "power/i2c.inc"
#endif

#include <esp_lcd_touch.h>

#if defined(CONFIG_DISPLAY_TOUCHSCREEN_CST816S)
#include <esp_lcd_touch_cst816s.h>
#define ESP_LCD_TOUCH_IO_I2C_CONFIG() ESP_LCD_TOUCH_IO_I2C_CST816S_CONFIG()
#define ESP_LCD_TOUCH_NEW_I2C(han, cfg, ret) esp_lcd_touch_new_i2c_cst816s(han, cfg, ret)
#elif defined(CONFIG_DISPLAY_TOUCHSCREEN_FT5X06)
#include <esp_lcd_touch_ft5x06.h>
#define ESP_LCD_TOUCH_IO_I2C_CONFIG() ESP_LCD_TOUCH_IO_I2C_FT5x06_CONFIG()
#define ESP_LCD_TOUCH_NEW_I2C(han, cfg, ret) esp_lcd_touch_new_i2c_ft5x06(han, cfg, ret)
#endif

static volatile bool shutdown_requested = false;
static volatile bool shutdown_finished = false;

esp_err_t _i2c_init_master(i2c_port_t port_num, int sda_io_num, int scl_io_num, i2c_master_bus_handle_t* handle);
esp_err_t _i2c_deinit(i2c_master_bus_handle_t handle);

static void touchscreen_task(void* ignored)
{
    esp_lcd_touch_handle_t ret_touch = NULL;
    // FIXME: check mirror flags?
    // NOTE: the touch panel extends below the main display over the navigation button
    // area - y_max must cover it, as it is used when mirroring coordinates on flip
    const esp_lcd_touch_config_t tp_cfg = {
        .x_max = CONFIG_DISPLAY_WIDTH + CONFIG_DISPLAY_OFFSET_X,
        .y_max = CONFIG_DISPLAY_HEIGHT + CONFIG_DISPLAY_OFFSET_Y + TOUCH_BUTTON_AREA,
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
    JADE_ASSERT(touch_i2c_handle);

    esp_lcd_panel_io_handle_t tp_io_handle = NULL;
    esp_lcd_panel_io_i2c_config_t tp_io_config = ESP_LCD_TOUCH_IO_I2C_CONFIG();
    tp_io_config.scl_speed_hz = CONFIG_I2C_MASTER_CLK;

    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(touch_i2c_handle, &tp_io_config, &tp_io_handle));
    JADE_ASSERT(tp_io_handle);

    ESP_ERROR_CHECK(ESP_LCD_TOUCH_NEW_I2C(tp_io_handle, &tp_cfg, &ret_touch));
    JADE_ASSERT(ret_touch);

    uint16_t touch_x[1];
    uint16_t touch_y[1];
    uint16_t touch_strength[1];
    uint8_t touch_cnt = 10;

#if DISPLAY_HAS_TOUCH_NAVBAR
    // Track the display orientation and mirror the touch Y coordinate to match, so the
    // virtual navbar button band keeps working when the display is flipped. Leave X
    // unchanged so the left/right navigation actions stay on the same physical sides.
    // Not on the M5 Core2, where the buttons are silk-screened on a fixed strip below
    // the display.
    bool touch_mirrored = false;
#endif

    // FIXME: don't allow multiple touches within 300 ms?
    while (!shutdown_requested) {
#if DISPLAY_HAS_TOUCH_NAVBAR
        const bool flipped = gui_get_flipped_orientation();
        if (touch_mirrored != flipped) {
            ESP_ERROR_CHECK(esp_lcd_touch_set_mirror_x(ret_touch, false));
            ESP_ERROR_CHECK(esp_lcd_touch_set_mirror_y(ret_touch, flipped));
            touch_mirrored = flipped;
        }
#endif
        if (esp_lcd_touch_read_data(ret_touch) == ESP_OK) {
            bool touchpad_pressed
                = esp_lcd_touch_get_coordinates(ret_touch, touch_x, touch_y, touch_strength, &touch_cnt, 1);
            if (touchpad_pressed) {
                const uint16_t first_third_end = CONFIG_DISPLAY_WIDTH / 3;
                const uint16_t middle_thirds_end = (CONFIG_DISPLAY_WIDTH * 2) / 3;
                if (touch_y[0] > CONFIG_DISPLAY_HEIGHT + CONFIG_DISPLAY_OFFSET_Y) {
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
    // Since IDF 5.5 the i2c bus cannot be deleted while devices are still attached
    ESP_ERROR_CHECK(esp_lcd_touch_del(ret_touch));
    ESP_ERROR_CHECK(esp_lcd_panel_io_del(tp_io_handle));
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
