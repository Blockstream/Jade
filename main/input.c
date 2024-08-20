#include "input.h"
#include "gui.h"
#include "iot_button.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "rotary_encoder.h"
#include "utils/malloc_ext.h"

#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
#include <driver/i2c.h>
#include <esp_lcd_touch.h>
#include <esp_lcd_touch_ft5x06.h>
#endif

void input_init(void) {}

#if defined(CONFIG_DISPLAY_TOUCHSCREEN)
static void touchscreen_task(void* ignored)
{
    esp_lcd_touch_handle_t ret_touch = NULL;
    const esp_lcd_touch_config_t tp_cfg = {
        .x_max = 320,
        .y_max = 240,
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

    esp_lcd_panel_io_handle_t tp_io_handle = NULL;
    const esp_lcd_panel_io_i2c_config_t tp_io_config = ESP_LCD_TOUCH_IO_I2C_FT5x06_CONFIG();
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c((esp_lcd_i2c_bus_handle_t)0, &tp_io_config, &tp_io_handle));
    ESP_ERROR_CHECK(esp_lcd_touch_new_i2c_ft5x06(tp_io_handle, &tp_cfg, &ret_touch));

    uint16_t touch_x[1];
    uint16_t touch_y[1];
    uint16_t touch_strength[1];
    uint8_t touch_cnt = 10;

    for (;;) {
        if (esp_lcd_touch_read_data(ret_touch) == ESP_OK) {
            bool touchpad_pressed
                = esp_lcd_touch_get_coordinates(ret_touch, touch_x, touch_y, touch_strength, &touch_cnt, 1);
            if (touchpad_pressed) {
                if (touch_y[0] > 200) {
                    if (touch_x[0] >= 10 && touch_x[0] <= 90) {
                        gui_prev();
                    } else if (touch_x[0] >= 120 && touch_x[0] <= 200) {
                        gui_front_click();
                    } else if (touch_x[0] >= 230 && touch_x[0] <= 310) {
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
}

void touchscreen_init(void)
{
    const BaseType_t retval = xTaskCreatePinnedToCore(
        &touchscreen_task, "touchscreen task", 3 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_PRIMARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create touchscreen task, xTaskCreatePinnedToCore() returned %d", retval);
}
#endif

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

void button_init(void)
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

#if !defined(CONFIG_BOARD_TYPE_JADE) && !defined(CONFIG_DISPLAY_TOUCHSCREEN)
static void wheel_common(button_handle_t* btn_handle_prev, button_handle_t* btn_handle_next)
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
    *btn_handle_prev = iot_button_create(&prev_btn_cfg);

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
    *btn_handle_next = iot_button_create(&next_btn_cfg);
}
#endif

#if defined(CONFIG_BOARD_TYPE_JADE)
// Original Jade v1.0 hardware has a rotary-encoder/wheel

// Set to true to enable tracking of rotary encoder at half step resolution
#define ENABLE_HALF_STEPS false

// Set to true to reverse the clockwise/counterclockwise sense
#ifdef CONFIG_INPUT_INVERT_WHEEL
#define FLIP_DIRECTION true
#else
#define FLIP_DIRECTION false
#endif

// Jade proper wheel init
static QueueHandle_t event_queue;
static rotary_encoder_info_t info = {};

void wheel_watch_task(void* unused)
{
    int32_t last_position = 0;

    for (;;) {
        rotary_encoder_event_t event = { 0 };
        if (xQueueReceive(event_queue, &event, 1000 / portTICK_PERIOD_MS) == pdTRUE) {
            if (event.state.position < last_position) {
                gui_prev();
            } else {
                gui_next();
            }

            last_position = event.state.position;
        }
    }

    JADE_LOGE("queue receive failed");
    vTaskDelete(NULL);
}

void wheel_init(void)
{
    // Create a queue for events from the rotary encoder driver.
    event_queue = rotary_encoder_create_queue();

    esp_err_t rc = gpio_install_isr_service(0);
    JADE_ASSERT(rc == ESP_OK);

    rc = rotary_encoder_init(&info, CONFIG_INPUT_WHEEL_A, CONFIG_INPUT_WHEEL_B);
    JADE_ASSERT(rc == ESP_OK);
    rc = rotary_encoder_enable_half_steps(&info, ENABLE_HALF_STEPS);
    JADE_ASSERT(rc == ESP_OK);
#ifdef FLIP_DIRECTION
    rc = rotary_encoder_flip_direction(&info);
    JADE_ASSERT(rc == ESP_OK);
#endif
    JADE_ASSERT(event_queue);

    // Tasks can read from this queue to receive up to date position information.
    rc = rotary_encoder_set_queue(&info, event_queue);
    JADE_ASSERT(rc == ESP_OK);

    const BaseType_t retval = xTaskCreatePinnedToCore(
        &wheel_watch_task, "wheel_watcher", 2 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create wheel_watcher task, xTaskCreatePinnedToCore() returned %d", retval);
}

#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY) || defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAYS3)
// wheel_init() to mock wheel with buttons

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

void wheel_init(void)
{
#if !defined(CONFIG_DISPLAY_TOUCHSCREEN)
    button_handle_t btn_handle_prev = NULL;
    button_handle_t btn_handle_next = NULL;
    wheel_common(&btn_handle_prev, &btn_handle_next);
    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_DOWN, button_pressed, &button_A_pressed);
    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_UP, button_released, &button_A_pressed);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_DOWN, button_pressed, &button_B_pressed);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_UP, button_released, &button_B_pressed);
#endif
}
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS) || defined(CONFIG_INPUT_ONE_BUTTON_MODE)
/*
M5StickC-Plus is similar to the TTGO T-Display in that it is two buttons,
but one of the buttons behaves badly when Bluetooth is active.
*/

// In the case of the M5StickC-Plus, the A button stops giving a "Released" event.
// As such, the A button simply looks for input when the button is pressed and calls "Prev"

static void button_A_pressed(void* arg, void* ctx) { gui_prev(); }

// The B button works fine, so it makes sense to have the "Front Click" as long click on the "B" Button
// (On the front face of the device) and also have the short click be "Next"

static uint64_t button_B_pressed_time = 0;
static void button_B_pressed(void* arg, void* ctx) { button_B_pressed_time = xTaskGetTickCount(); }

static void button_B_released(void* arg, void* ctx)
{
    const uint64_t current = xTaskGetTickCount();
    if ((current - button_B_pressed_time) > 50) {
        gui_front_click();
    } else {
        gui_next();
    }
}

void wheel_init(void)
{
    button_handle_t btn_handle_prev = NULL;
    button_handle_t btn_handle_next = NULL;
    wheel_common(&btn_handle_prev, &btn_handle_next);
    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_DOWN, button_A_pressed, NULL);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_DOWN, button_B_pressed, NULL);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_UP, button_B_released, NULL);
}
#else
// wheel_init() to mock wheel with buttons
// Long press buttons mocks wheel spin (multiple events)
static void button_A_pressed(void* arg, void* ctx) { gui_prev(); }

static void button_B_pressed(void* arg, void* ctx) { gui_next(); }

void wheel_init(void)
{
#if !defined(CONFIG_DISPLAY_TOUCHSCREEN)
    button_handle_t btn_handle_prev = NULL;
    button_handle_t btn_handle_next = NULL;
    wheel_common(&btn_handle_prev, &btn_handle_next);
    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_UP, button_A_pressed, NULL);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_UP, button_B_pressed, NULL);

    // M5Stack-Basic/Fire hw has three buttons, but the A button behaves behaves badly when Bluetooth is active.
    // In this case the A button generates constant input if serial input is enabled, so the simplest fix is to remove
    // the ability to hold the button down (ie. do not add serial event handlers).
#if (!defined(CONFIG_BT_ENABLED)) || (!defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY) && !defined(CONFIG_BOARD_TYPE_M5_FIRE))
    iot_button_register_cb(btn_handle_prev, BUTTON_LONG_PRESS_HOLD, button_A_pressed, NULL);
    iot_button_register_cb(btn_handle_next, BUTTON_LONG_PRESS_HOLD, button_B_pressed, NULL);
#endif
#endif
}
#endif // CONFIG_BOARD_TYPE_xxx
