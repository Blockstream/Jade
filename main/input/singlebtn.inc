#include "gui.h"

#include "iot_button.h"

// M5StickC-Plus is similar to the TTGO T-Display in that it is two buttons,
// but one of the buttons behaves badly when Bluetooth is active.
// In the case of the M5StickC-Plus, the A button stops giving a "Released" event.
// As such, the A button simply looks for input when the button is pressed and calls "Prev"
// Holding down A button will send repeat events for faster navigation.
// The B button works fine, so it makes sense to have the "Front Click" as long click on the "B" Button
// (on the front face of the device) and also have the short click be "Next"
// NOTE: button B does not raise repeat events.

static bool button_B_event_outstanding = false;

static void button_A_pressed(void* arg, void* ctx) { gui_prev(); }

static void button_B_pressed(void* arg, void* ctx) { button_B_event_outstanding = true; }

static void button_B_long_press(void* arg, void* ctx)
{
    if (button_B_event_outstanding) {
        button_B_event_outstanding = false;
        gui_front_click();
    }
}

static void button_B_released(void* arg, void* ctx)
{
    if (button_B_event_outstanding) {
        button_B_event_outstanding = false;
        gui_next();
    }
}

void navigation_init(void)
{
    button_config_t prev_btn_cfg = {
    .type = BUTTON_TYPE_GPIO,
    .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
    .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    .gpio_button_config = {
        .gpio_num = CONFIG_INPUT_BTN_A,
        .active_level = 0,
        },
    };
    button_handle_t btn_handle_prev = iot_button_create(&prev_btn_cfg);

    button_config_t next_btn_cfg = {
    .type = BUTTON_TYPE_GPIO,
    .long_press_time = CONFIG_BUTTON_LONG_PRESS_TIME_MS,
    .short_press_time = CONFIG_BUTTON_SHORT_PRESS_TIME_MS,
    .gpio_button_config = {
        .gpio_num = CONFIG_INPUT_BTN_B,
#ifdef CONFIG_BUTTON_B_ACTIVE_HIGH
        .active_level = 1,
#else
        .active_level = 0,
#endif
        },
    };
    button_handle_t btn_handle_next = iot_button_create(&next_btn_cfg);

    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_DOWN, button_A_pressed, NULL);
    iot_button_register_cb(btn_handle_prev, BUTTON_LONG_PRESS_HOLD, button_A_pressed, NULL);

    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_DOWN, button_B_pressed, NULL);
    iot_button_register_cb(btn_handle_next, BUTTON_LONG_PRESS_START, button_B_long_press, NULL);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_UP, button_B_released, NULL);
}

static void select_init(void)
{
    // No-op - navigation_init() initialises the buttons
}
