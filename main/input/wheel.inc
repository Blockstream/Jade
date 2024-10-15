#include "gui.h"
#include "jade_assert.h"
#include "jade_tasks.h"

#include "rotary_encoder.h"

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

static void wheel_watch_task(void* unused)
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

void navigation_init(void)
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
