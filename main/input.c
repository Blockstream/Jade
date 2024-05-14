#include "input.h"
#include "gui.h"
#include "iot_button.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "rotary_encoder.h"
#include "utils/malloc_ext.h"

void input_init(void) {}

#ifdef CONFIG_INPUT_FRONT_SW
static void button_front_release(void* arg, void* ctx) { gui_front_click(); }

static void button_front_long(void* arg, void* ctx)
{
    JADE_LOGW("front-btn long-press ignored");
    // gui_front_click();
}
#endif

#ifdef CONFIG_INPUT_WHEEL_SW
static void button_wheel_release(void* arg, void* ctx) { gui_wheel_click(); }

static void button_wheel_long(void* arg, void* ctx)
{
    JADE_LOGW("wheel long-press ignored");
    // gui_wheel_click();
}
#endif

void button_init(void)
{
#ifdef CONFIG_INPUT_FRONT_SW
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

#ifdef CONFIG_INPUT_WHEEL_SW
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

#ifndef CONFIG_BOARD_TYPE_JADE
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

void wheel_uninit(bool uninstall_gpio_isr_service)
{
    const esp_err_t rc = rotary_encoder_uninit(&info);
    JADE_ASSERT(rc == ESP_OK);
    if (uninstall_gpio_isr_service) {
        gpio_uninstall_isr_service();
    }
}

/* reinit reuses same queue and Task */
void wheel_reinit(bool install_gpio_isr_service)
{
    if (install_gpio_isr_service) {
        const esp_err_t rc = gpio_install_isr_service(0);
        JADE_ASSERT(rc == ESP_OK);
    }
    // Initialise the rotary encoder device with the GPIOs for A and B signals
    esp_err_t rc = rotary_encoder_init(&info, CONFIG_INPUT_WHEEL_A, CONFIG_INPUT_WHEEL_B);
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
}

void wheel_init(void)
{
    // Create a queue for events from the rotary encoder driver.
    event_queue = rotary_encoder_create_queue();

    wheel_reinit(/* install_gpio_isr_service */ true);

    const BaseType_t retval = xTaskCreatePinnedToCore(
        &wheel_watch_task, "wheel_watcher", 2 * 1024, NULL, JADE_TASK_PRIO_WHEEL, NULL, JADE_CORE_SECONDARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create wheel_watcher task, xTaskCreatePinnedToCore() returned %d", retval);
}

#elif defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY)
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
    button_handle_t btn_handle_prev = NULL;
    button_handle_t btn_handle_next = NULL;
    wheel_common(&btn_handle_prev, &btn_handle_next);
    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_DOWN, button_pressed, &button_A_pressed);
    iot_button_register_cb(btn_handle_prev, BUTTON_PRESS_UP, button_released, &button_A_pressed);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_DOWN, button_pressed, &button_B_pressed);
    iot_button_register_cb(btn_handle_next, BUTTON_PRESS_UP, button_released, &button_B_pressed);
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
}
#endif // CONFIG_BOARD_TYPE_xxx
