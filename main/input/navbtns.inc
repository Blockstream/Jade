#include "gui.h"
#include "jade_assert.h"

#include "button_gpio.h"
#include "iot_button.h"

// Slightly complicated to allow both-buttons pressed to mock selection button
// To acheive this we only action the button when it is released - and we check
// to see if the other button is depressed at the time.
static bool button_A_pressed = false;
static bool button_B_pressed = false;

static void button_pressed(void* arg, void* ctx)
{
    JADE_ASSERT(ctx);
    bool* button = ctx;
    *button = true;
}

static void button_released(void* arg, void* ctx)
{
    JADE_ASSERT(ctx);

    // button_A_pressed or button_B_pressed passed in ctx to indicate which was released
    if (button_A_pressed && button_B_pressed) {
        gui_front_click();
    } else if (button_A_pressed && ctx == &button_A_pressed) {
        gui_prev();
    } else if (button_B_pressed && ctx == &button_B_pressed) {
        gui_next();
    }

    // Clear both flags here so we ignore the second button release when both pressed
    button_B_pressed = false;
    button_A_pressed = false;
}

#if (!defined(CONFIG_BT_ENABLED)) || (!defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY) && !defined(CONFIG_BOARD_TYPE_M5_FIRE))
static void button_held(void* arg, void* ctx)
{
    JADE_ASSERT(ctx);

    // Ignore both (or neither) button held down
    // (We don't want to repeat the select action, only navigation)
    if (button_A_pressed == button_B_pressed) {
        return;
    } else if (button_A_pressed && ctx == &button_A_pressed) {
        gui_prev();
    } else if (button_B_pressed && ctx == &button_B_pressed) {
        gui_next();
    }
}
#endif

void navigation_init(void)
{
    const button_config_t prev_btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    const button_gpio_config_t prev_btn_gpio_cfg = {
        .gpio_num = CONFIG_INPUT_BTN_A,
        .active_level = 0,
    };

    button_handle_t btn_handle_prev = NULL;
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&prev_btn_cfg, &prev_btn_gpio_cfg, &btn_handle_prev));

    JADE_ASSERT(btn_handle_prev);

    const button_config_t next_btn_cfg = {
        .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
        .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    };

    const button_gpio_config_t next_btn_gpio_cfg = {
        .gpio_num = CONFIG_INPUT_BTN_B,
#ifdef CONFIG_BUTTON_B_ACTIVE_HIGH
        .active_level = 1,
#else
        .active_level = 0,
#endif
    };

    button_handle_t btn_handle_next = NULL;
    ESP_ERROR_CHECK(iot_button_new_gpio_device(&next_btn_cfg, &next_btn_gpio_cfg, &btn_handle_next));

    JADE_ASSERT(btn_handle_next);

    ESP_ERROR_CHECK(
        iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_DOWN, NULL, button_pressed, &button_A_pressed));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_UP, NULL, button_released, &button_A_pressed));
    ESP_ERROR_CHECK(
        iot_button_register_cb(btn_handle_next, BUTTON_PRESS_DOWN, NULL, button_pressed, &button_B_pressed));
    ESP_ERROR_CHECK(iot_button_register_cb(btn_handle_next, BUTTON_PRESS_UP, NULL, button_released, &button_B_pressed));

    // M5Stack-Basic/Fire hw has three buttons, but the A button behaves behaves badly when Bluetooth is active.
    // In this case the A button generates constant input if serial input is enabled, so the simplest fix is to remove
    // the ability to hold the button down (ie. do not add serial event handlers).
#if (!defined(CONFIG_BT_ENABLED)) || (!defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY) && !defined(CONFIG_BOARD_TYPE_M5_FIRE))
    ESP_ERROR_CHECK(
        iot_button_register_cb(btn_handle_prev, BUTTON_LONG_PRESS_HOLD, NULL, button_held, &button_A_pressed));
    ESP_ERROR_CHECK(
        iot_button_register_cb(btn_handle_next, BUTTON_LONG_PRESS_HOLD, NULL, button_held, &button_B_pressed));
#endif
}
