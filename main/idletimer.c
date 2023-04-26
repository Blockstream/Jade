#include "idletimer.h"
#include "gui.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "keychain.h"
#include "power.h"
#include "storage.h"
#include "ui.h"
#include "utils/event.h"

#define DEFAULT_IDLE_TIMEOUT_SECS 600
#define TIMEOUT_SLEEP_PERIOD_SECS 60
#define KEEP_AWAKE_WARNING_SECS 10

#define SECS_TO_TICKS(secs) (secs * 1000 / portTICK_PERIOD_MS)

// The 'last activity' counter, protected by a mutex
static TickType_t last_activity_registered = 0;
static SemaphoreHandle_t last_activity_mutex = NULL;
static uint16_t min_timeout_override_secs = 0;

// Function to (temporarily?) set a minimum timeout value
// eg. to set temporarilty while doing a 'slow' operation where
// you don't want the hw hitting the idle timeout and shutting down.
// eg. using the camera to scan large qrs or similar.
void idletimer_set_min_timeout_secs(const uint16_t min_timeout_secs) { min_timeout_override_secs = min_timeout_secs; }

// Function to register activity
void idletimer_register_activity(void)
{
    JADE_ASSERT(last_activity_mutex);

    // Take the semaphore and put the tick time in the counter
    while (xSemaphoreTake(last_activity_mutex, portMAX_DELAY) != pdTRUE) {
        // wait for the mutex
    }
    last_activity_registered = xTaskGetTickCount();
    xSemaphoreGive(last_activity_mutex);
}

// Function to get last registered activity time
static TickType_t get_last_registered_activity(void)
{
    JADE_ASSERT(last_activity_mutex);

    // Get the last activity time
    while (xSemaphoreTake(last_activity_mutex, portMAX_DELAY) != pdTRUE) {
        // wait for the mutex
    }
    const TickType_t last_activity = last_activity_registered;
    xSemaphoreGive(last_activity_mutex);
    return last_activity;
}

// The idle timer task - loops, waking periodically to check the time since
// the last registered user activity.  If sufficiently long ago, deactivates
// the device, after having diplayed a warning/cancel screen for a few seconds.
static void idletimer_task(void* ignore)
{
    const TickType_t period = SECS_TO_TICKS(TIMEOUT_SLEEP_PERIOD_SECS);
    while (true) {
        // Always fetch the timeout period, in case the user has changed it
        uint16_t timeout_secs = storage_get_idle_timeout();
        if (timeout_secs < min_timeout_override_secs) {
            timeout_secs = min_timeout_override_secs;
        }
        const TickType_t timeout = SECS_TO_TICKS(timeout_secs);

        const TickType_t last_activity = get_last_registered_activity();
        const TickType_t checktime = xTaskGetTickCount();

        // See if the last activity was sufficiently long ago
        const TickType_t projected_timeout_time = last_activity + timeout;
        JADE_LOGI(
            "Idle-timeout check - last-activity: %lu, timeout period: %lu, projected-timeout: %lu, checktime: %lu",
            last_activity, timeout, projected_timeout_time, checktime);

        if (projected_timeout_time <= checktime) {
            // Timeout elapsed, prepare to power-off device
            // Give user last chance ...
            JADE_LOGW("Idle-timeout elapsed - showing warning screen");

            gui_activity_t* prior_activity = gui_current_activity();
            gui_activity_t* activity
                = display_message_activity_two_lines("Jade preparing to power-off!", "Press button to keep awake.");
            bool ret = gui_activity_wait_event(
                activity, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL, SECS_TO_TICKS(KEEP_AWAKE_WARNING_SECS));

#ifdef CONFIG_DEBUG_UNATTENDED_CI
            // Debug ci build should never idle out - mock button press
            JADE_LOGW("Idle-timeout elapsed - no-display/CI/test build - preventing timeout.");
            ret = true;
#endif

            // Check the activity time again, if it was recent we can cancel the power-off
            if (ret || get_last_registered_activity() > checktime) {
                // User pressed something or message arrived, cancel power-off
                JADE_LOGI("Cancelling idle-timeout power-off, next check in %lu", period);

                // Replace prior activity if we're still current
                if (gui_current_activity() == activity) {
                    gui_set_current_activity(prior_activity);
                }

                // Sleep until the next check
                vTaskDelay(period);
                continue;
            }

            JADE_LOGW("Idle-timeout elapsed  - powering-off device");
            keychain_clear();
            power_shutdown();
        }

        // Not timed out yet.
        // If projected timeout is imminent, only sleep until then.
        // Otherwise sleep for our regular checking period.
        // (We have to wake up before the projected timeout in case the user
        // reduces the timeout period of the device in the interim.)
        const TickType_t delay
            = checktime + period > projected_timeout_time ? projected_timeout_time - checktime : period;
        JADE_LOGI("Unit not idle, next check in %lu", delay);
        vTaskDelay(delay);
    }
}

void idletimer_init(void)
{
    // Create mutext semaphore.
    last_activity_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(last_activity_mutex);

    // Default timeout time if not set
    const uint16_t timeout_secs = storage_get_idle_timeout();
    if (timeout_secs == 0) {
        storage_set_idle_timeout(DEFAULT_IDLE_TIMEOUT_SECS);
    }

    // Initialise the 'last activity' to now
    idletimer_register_activity();

    // Kick off the idletimer task
    const BaseType_t retval = xTaskCreatePinnedToCore(
        idletimer_task, "idle_timeout", 2 * 1024, NULL, JADE_TASK_PRIO_IDLETIMER, NULL, JADE_CORE_PRIMARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create idle_timeout task, xTaskCreatePinnedToCore() returned %d", retval);
}
