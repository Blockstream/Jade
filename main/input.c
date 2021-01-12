#include "input.h"
#include "gui.h"
#include "iot_button.h"
#include "jade_assert.h"
#include "rotary_encoder.h"
#include "utils/malloc_ext.h"

static bool invert_wheel = false;

void input_init()
{
    const esp_err_t rc = gpio_install_isr_service(0);
    JADE_ASSERT(rc == ESP_OK);
    invert_wheel = false;
}

void set_invert_wheel(bool inverted) { invert_wheel = inverted; }

static void button_front_release(void* arg) { gui_front_click(); }

static void button_front_long(void* arg)
{
    JADE_LOGW("front-btn long-press ignored");
    // gui_front_click();
}

static void button_wheel_release(void* arg) { gui_wheel_click(); }

static void button_wheel_long(void* arg)
{
    JADE_LOGW("wheel long-press ignored");
    // gui_wheel_click();
}

void button_init()
{
    button_handle_t btn_handle_front = iot_button_create(BUTTON_FRONT, BUTTON_ACTIVE_LOW);
    iot_button_set_evt_cb(btn_handle_front, BUTTON_CB_RELEASE, button_front_release, NULL);
    iot_button_add_custom_cb(btn_handle_front, 1, button_front_long, NULL);

    button_handle_t btn_handle_wheel = iot_button_create(BUTTON_ENC, BUTTON_ACTIVE_LOW);
    iot_button_set_evt_cb(btn_handle_wheel, BUTTON_CB_RELEASE, button_wheel_release, NULL);
    iot_button_add_custom_cb(btn_handle_wheel, 1, button_wheel_long, NULL);
}

static inline void wheel_prev()
{
    if (invert_wheel) {
        gui_next();
    } else {
        gui_prev();
    }
}

static inline void wheel_next()
{
    if (invert_wheel) {
        gui_prev();
    } else {
        gui_next();
    }
}

#if defined(CONFIG_BOARD_TYPE_M5_FIRE) || defined(CONFIG_BOARD_TYPE_M5_BLACK_GRAY)                                     \
    || defined(CONFIG_BOARD_TYPE_TTGO_TDISPLAY)

// M5 wheel_init() to mock jade wheel
static bool button_A_pressed = false;
static bool button_B_pressed = false;

static void button_pressed(void* arg)
{
    bool* button = arg;
    *button = true;
}

static void button_handle_two_buttonsA(void* arg)
{
    if (button_B_pressed) {
        gui_front_click();
    } else if (button_A_pressed) {
        wheel_next();
    }
    button_B_pressed = false;
    button_A_pressed = false;
}

static void button_handle_two_buttonsB(void* arg)
{
    if (button_A_pressed) {
        gui_front_click();
    } else if (button_B_pressed) {
        wheel_prev();
    }
    button_B_pressed = false;
    button_A_pressed = false;
}

void wheel_init()
{
    button_handle_t btn_handle_prev = iot_button_create(CONFIG_INPUT_BTN_A, BUTTON_ACTIVE_LOW);
    iot_button_set_evt_cb(btn_handle_prev, BUTTON_CB_PUSH, button_pressed, &button_A_pressed);
    iot_button_set_evt_cb(btn_handle_prev, BUTTON_CB_RELEASE, button_handle_two_buttonsA, NULL);

    button_handle_t btn_handle_next = iot_button_create(CONFIG_INPUT_BTN_B, BUTTON_ACTIVE_LOW);
    iot_button_set_evt_cb(btn_handle_next, BUTTON_CB_PUSH, button_pressed, &button_B_pressed);
    iot_button_set_evt_cb(btn_handle_next, BUTTON_CB_RELEASE, button_handle_two_buttonsB, NULL);
}

#else

// Jade proper wheel init
static QueueHandle_t event_queue;

void wheel_watch_task(void* info_void)
{
    rotary_encoder_info_t* info = (rotary_encoder_info_t*)info_void;
    int32_t last_position = 0;

    for (;;) {
        rotary_encoder_event_t event = { 0 };
        if (xQueueReceive(event_queue, &event, 1000 / portTICK_PERIOD_MS) == pdTRUE) {
            if (event.state.position < last_position) {
                wheel_prev();
            } else {
                wheel_next();
            }

            last_position = event.state.position;
        }
    }

    JADE_LOGE("queue receive failed");
    const esp_err_t rc = rotary_encoder_uninit(info);
    JADE_ASSERT(rc == ESP_OK);
    free(info);

    vTaskDelete(NULL);
}

void wheel_init()
{
    // Initialise the rotary encoder device with the GPIOs for A and B signals
    rotary_encoder_info_t* info = (rotary_encoder_info_t*)JADE_MALLOC(sizeof(rotary_encoder_info_t));
    esp_err_t rc = rotary_encoder_init(info, ROT_ENC_A_GPIO, ROT_ENC_B_GPIO);
    JADE_ASSERT(rc == ESP_OK);
    rc = rotary_encoder_enable_half_steps(info, ENABLE_HALF_STEPS);
    JADE_ASSERT(rc == ESP_OK);
#ifdef FLIP_DIRECTION
    rc = rotary_encoder_flip_direction(info);
    JADE_ASSERT(rc == ESP_OK);
#endif

    // Create a queue for events from the rotary encoder driver.
    event_queue = rotary_encoder_create_queue();
    // Tasks can read from this queue to receive up to date position information.
    rc = rotary_encoder_set_queue(info, event_queue);
    JADE_ASSERT(rc == ESP_OK);

#ifdef CONFIG_FREERTOS_UNICORE
    const BaseType_t core_used = 0;
#else
    const BaseType_t core_used = 1;
#endif
    const BaseType_t retval
        = xTaskCreatePinnedToCore(&wheel_watch_task, "wheel_watcher", 2 * 1024, info, 5, NULL, core_used);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create wheel_watcher task, xTaskCreatePinnedToCore() returned %d", retval);
}

#endif
