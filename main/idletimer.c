#ifndef AMALGAMATED_BUILD
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
#define UI_SCREEN_IDLE_TIMEOUT_SECS 90
#define TIMEOUT_SLEEP_PERIOD_SECS 60
#define KEEP_AWAKE_WARNING_SECS 10

#define SECS_TO_TICKS(secs) (secs * 1000 / portTICK_PERIOD_MS)

// The 'last activity' counters, protected by a mutex
static TickType_t last_activity_registered = 0;
static TickType_t last_ui_activity_registered = 0;
static SemaphoreHandle_t last_activity_mutex = NULL;
static uint16_t min_timeout_override_secs = 0;
static bool screen_dimmed = false;

// Set if unit reboots idle/screen powered off
// NOTE: we do not use an 'is_idle' bool here, as the first time the unit boots with
// this variable being read (eg. after the initial OTA to this version) the value will
// be uninitialised (and very unlikely to be 0x00/false).
typedef enum { NORMAL, IDLE } idle_state_t;
static __NOINIT_ATTR idle_state_t idle_state;

static void set_screen_dimmed(const bool dimmed)
{
    power_backlight_on(dimmed ? BACKLIGHT_MIN : storage_get_brightness());
    screen_dimmed = dimmed;
}

// Function to (temporarily?) set a minimum timeout value
// eg. to set temporarilty while doing a 'slow' operation where
// you don't want the hw hitting the idle timeout and shutting down.
// eg. using the camera to scan large qrs or similar.
void idletimer_set_min_timeout_secs(const uint16_t min_timeout_secs) { min_timeout_override_secs = min_timeout_secs; }

// Function to register activity
bool idletimer_register_activity(const bool is_ui)
{
    JADE_ASSERT(last_activity_mutex);

    // Take the semaphore and put the tick time in the counter
    while (xSemaphoreTake(last_activity_mutex, portMAX_DELAY) != pdTRUE) {
        // wait for the mutex
    }

    // Register activity, and optionally 'ui activity'
    idle_state = NORMAL;
    last_activity_registered = xTaskGetTickCount();
    if (is_ui) {
        last_ui_activity_registered = last_activity_registered;
    }

    xSemaphoreGive(last_activity_mutex);

    // UI activity ensures screen fully on
    if (is_ui && screen_dimmed) {
        JADE_LOGI("Activity while screen disabled - powering screen");
        set_screen_dimmed(false);
        return true;
    }
    return false;
}

// Function to get last registered activity time
static TickType_t get_last_registered_activity(const bool ui)
{
    JADE_ASSERT(last_activity_mutex);

    // Get the last activity time
    while (xSemaphoreTake(last_activity_mutex, portMAX_DELAY) != pdTRUE) {
        // wait for the mutex
    }
    const TickType_t last_activity = ui ? last_ui_activity_registered : last_activity_registered;
    xSemaphoreGive(last_activity_mutex);
    return last_activity;
}

static bool show_timeout_warning_screen(void)
{
    gui_activity_t* const prior_activity = gui_current_activity();

    const char* message[] = { "Jade preparing to sleep", "", "Press button to", "keep awake." };
    gui_activity_t* const act = display_message_activity(message, 4);
    const bool ret = gui_activity_wait_event(
        act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL, SECS_TO_TICKS(KEEP_AWAKE_WARNING_SECS));

    // Replace prior activity if we're still current
    if (gui_current_activity() == act) {
        gui_set_current_activity(prior_activity);
    }

    return ret;
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

        // NOTE: timeout secs set to UINT16_MAX means 'never time-out'
        const bool idle_timeout_disabled = (timeout_secs == UINT16_MAX);
        const TickType_t timeout = SECS_TO_TICKS(timeout_secs);

        const TickType_t last_activity = get_last_registered_activity(false);
        const TickType_t checktime = xTaskGetTickCount();

        // See if the last activity was sufficiently long ago
        const TickType_t projected_timeout_time = last_activity + timeout;
        JADE_LOGI(
            "Idle-timeout check - last-activity: %lu, timeout period: %lu, projected-timeout: %lu, checktime: %lu",
            last_activity, timeout, projected_timeout_time, checktime);
        JADE_LOGI("Idle task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));

        // If we are already flagged as idle, or the idle-timeout is explicitly disabled, we skip these checks
        if (!idle_timeout_disabled && (projected_timeout_time <= checktime)) {
            // If usb is connected instead of deactivating we can reboot (if wallet loaded) and dim the screen
            typedef enum { SCREEN_DIMMED, REBOOT, POWER_OFF } reset_action_t;
            reset_action_t action = !usb_connected() ? POWER_OFF : (keychain_get() ? REBOOT : SCREEN_DIMMED);
            JADE_LOGW("Idle-timeout elapsed - action: %u", action);

            if (action != SCREEN_DIMMED) {
                // reboot/power-off device - give user last chance ...
                const bool acted = show_timeout_warning_screen();

                // Check the activity time again, if it was recent we can cancel the power-off
                if (acted || get_last_registered_activity(false) > checktime) {
                    // User pressed something or message arrived - sleep until the next check
                    JADE_LOGI("Cancelling idle-timeout, next check in %lu", period);
                    vTaskDelay(period);
                    continue;
                }

#if defined(CONFIG_DEBUG_UNATTENDED_CI) || defined(CONFIG_ETH_USE_OPENETH)
                // Don't reboot or power-off in unattended/ci build or in emulator
                action = SCREEN_DIMMED;
#endif
            }

            // Sometimes we can reboot and/or dim the screen rather than power-off
            // eg. if connected via usb this may be a more sensible option.
            idle_state = IDLE;
            switch (action) {
            case POWER_OFF:
                power_backlight_off();
                keychain_clear();
                power_shutdown();
                break;
            case REBOOT:
                power_backlight_off();
                keychain_clear();
                esp_restart();
                break;
            default:
                if (!screen_dimmed) {
                    set_screen_dimmed(true);
                }
            }
        }

        // If we did not idle time-out entirely we may still dim the screen if no physical interaction
        if (!screen_dimmed) {
            const TickType_t last_ui_activity = get_last_registered_activity(true);
            const TickType_t projected_ui_timeout_time = last_ui_activity + SECS_TO_TICKS(UI_SCREEN_IDLE_TIMEOUT_SECS);
            if (projected_ui_timeout_time <= checktime) {
                // deactivate the screen
                JADE_LOGW("Idle-timeout - dimming screen");
                set_screen_dimmed(true);
            }
        }

        // If projected timeout is imminent, only sleep until then.
        // Otherwise sleep for our regular checking period.
        // (We have to wake up before the projected timeout in case the user
        // reduces the timeout period of the device in the interim.)
        const TickType_t delay = projected_timeout_time > checktime && projected_timeout_time < checktime + period
            ? projected_timeout_time - checktime
            : period;
        JADE_LOGI("Next check in %lu", delay);
        vTaskDelay(delay);
    }
}

void idletimer_init(void)
{
    const esp_reset_reason_t reset_reason = esp_reset_reason();
    JADE_LOGI("esp_reset_reason: %u", reset_reason);

    // Reset idle_state to NORMAL if this is not a software restart.
    // (If this *is* a sw restart, then 'idle_state' retains its value)
    if (reset_reason != ESP_RST_SW) {
        JADE_LOGI("Resetting idle-state flag");
        idle_state = NORMAL;
    }
    JADE_LOGI("idle_state: %u", idle_state);

    // If this is a soft-reset due to inactivity, do not power the screen.
    // In most cases - we power the screen backlight.
    const bool start_dimmed = (idle_state == IDLE);
    JADE_LOGI("powering screen, dimmed mode: %u", start_dimmed);
    set_screen_dimmed(start_dimmed);

    // Create mutext semaphore.
    last_activity_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(last_activity_mutex);

    // Default timeout time if not set
    const uint16_t timeout_secs = storage_get_idle_timeout();
    if (timeout_secs == 0) {
        storage_set_idle_timeout(DEFAULT_IDLE_TIMEOUT_SECS);
    }

    // Kick off the idletimer task
#ifdef CONFIG_IDF_TARGET_ESP32S3
    const size_t stack_size = (2 * 1024) + 512;
#else
    const size_t stack_size = 2 * 1024;
#endif
    const BaseType_t retval = xTaskCreatePinnedToCore(
        idletimer_task, "idle_timeout", stack_size, NULL, JADE_TASK_PRIO_IDLETIMER, NULL, JADE_CORE_PRIMARY);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create idle_timeout task, xTaskCreatePinnedToCore() returned %d", retval);
}
#endif // AMALGAMATED_BUILD
