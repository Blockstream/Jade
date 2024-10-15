#include "gui.h"
#include "jade_log.h"

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
    button_config_t front_sw_btn_cfg = {
    .type = BUTTON_TYPE_GPIO,
    .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
    .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    .gpio_button_config = {
        .gpio_num = CONFIG_INPUT_FRONT_SW,
        .active_level = 0,
        },
    };
    button_handle_t btn_handle_front = iot_button_create(&front_sw_btn_cfg);
    iot_button_register_cb(btn_handle_front, BUTTON_PRESS_UP, button_front_release, NULL);
    iot_button_register_cb(btn_handle_front, BUTTON_LONG_PRESS_START, button_front_long, NULL);
#endif

#if CONFIG_INPUT_WHEEL_SW >= 0
    button_config_t wheel_btn_cfg = {
    .type = BUTTON_TYPE_GPIO,
    .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
    .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    .gpio_button_config = {
        .gpio_num = CONFIG_INPUT_WHEEL_SW,
        .active_level = 0,
        },
    };
    button_handle_t btn_handle_wheel = iot_button_create(&wheel_btn_cfg);
    iot_button_register_cb(btn_handle_wheel, BUTTON_PRESS_UP, button_wheel_release, NULL);
    iot_button_register_cb(btn_handle_wheel, BUTTON_LONG_PRESS_START, button_wheel_long, NULL);
#endif
}
