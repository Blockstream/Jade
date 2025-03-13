#include "gui.h"
#include "jade_assert.h"
#include "jade_log.h"

#include "button_gpio.h"
#include "iot_button.h"

#if CONFIG_INPUT_FRONT_SW >= 0
static void button_front_release(void* arg, void* ctx) { gui_front_click(); }

static void button_front_long(void* arg, void* ctx)
{
    JADE_LOGW("front-btn long-press ignored");
    // gui_front_click();
}
#endif

#if CONFIG_INPUT_WHEEL_SW >= 0
static void button_wheel_release(void* arg, void* ctx) { gui_wheel_click(); }

static void button_wheel_long(void* arg, void* ctx)
{
    JADE_LOGW("wheel long-press ignored");
    // gui_wheel_click();
}
#endif

void select_init(void)
{
#if CONFIG_INPUT_FRONT_SW >= 0
    const button_config_t front_sw_btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    const button_gpio_config_t front_btn_gpio_cfg = {
        .gpio_num = CONFIG_INPUT_FRONT_SW,
        .active_level = 0,
    };

    button_handle_t btn_handle_front = NULL;
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&front_sw_btn_cfg, &front_btn_gpio_cfg, &btn_handle_front));

    JADE_ASSERT(btn_handle_front);

    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle_front, BUTTON_PRESS_UP, NULL, button_front_release, NULL));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle_front, BUTTON_LONG_PRESS_START, NULL, button_front_long, NULL));
#endif

#if CONFIG_INPUT_WHEEL_SW >= 0
    const button_config_t wheel_btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    const button_gpio_config_t wheel_btn_gpio_cfg = {
        .gpio_num = CONFIG_INPUT_WHEEL_SW,
        .active_level = 0,
    };

    button_handle_t btn_handle_wheel = NULL;
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&wheel_btn_cfg, &wheel_btn_gpio_cfg, &btn_handle_wheel));

    JADE_ASSERT(btn_handle_wheel);

    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle_wheel, BUTTON_PRESS_UP, NULL, button_wheel_release, NULL));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle_wheel, BUTTON_LONG_PRESS_START, NULL, button_wheel_long, NULL));
#endif
}
