#ifndef AMALGAMATED_BUILD
#include "usbhmsc.h"

#include <esp_err.h>
#include <esp_vfs.h>
#include <esp_vfs_fat.h>
#include <freertos/task.h>
#include <msc_host.h>
#include <msc_host_vfs.h>
#include <stdlib.h>
#include <usb/usb_host.h>

#include "../jade_assert.h"
#include "../jade_log.h"
#include "../jade_tasks.h"
#include "../power.h"

typedef enum {
    USBSTATE_NONE = 0x00, // USB task is not started/initialized yet
    USBSTATE_USB_INSTALLED = 0x01, // usb_host_install() called
    USBSTATE_MSC_INSTALLED = 0x02, // msc_host_install() called
    USBSTATE_WORKER_SHUTDOWN = 0x20, // USB clients disconnected, worker task has shutdown
    USBSTATE_SHUTDOWN_REQUESTED = 0x40, // USB task asked to shutdown
    USBSTATE_ERROR = 0x80, // An error occurred
    USBSTATE_TERMINAL_EVENT = USBSTATE_SHUTDOWN_REQUESTED | USBSTATE_ERROR,
} usbstorage_state_t;

static SemaphoreHandle_t usbstorage_mutex = NULL;
static TaskHandle_t usbstorage_task = NULL;
static EventGroupHandle_t usbstorage_flags = NULL;
static QueueHandle_t usbstorage_msc_queue = NULL;
static usbstorage_state_t usbstorage_state = USBSTATE_NONE;
// Disable logging when switching from USB serial to USB storage
#define USBSTORAGE_DISABLE_LOGGING
#ifdef USBSTORAGE_DISABLE_LOGGING
static esp_log_level_t initial_log_level;
#endif

static usbstorage_state_t usbstorage_state_get(void)
{
    usbstorage_state_t state;
    JADE_SEMAPHORE_TAKE(usbstorage_mutex);
    state = usbstorage_state;
    JADE_SEMAPHORE_GIVE(usbstorage_mutex);
    return state;
}

static void usbstorage_state_set(const usbstorage_state_t state)
{
    JADE_SEMAPHORE_TAKE(usbstorage_mutex);
    usbstorage_state |= state;
    JADE_SEMAPHORE_GIVE(usbstorage_mutex);
}

static void msc_event_cb(const msc_host_event_t* event, void* ignore)
{
    if (event->event == MSC_DEVICE_CONNECTED) {
        JADE_LOGI("DEVICE_CONNECTED %d", (int)event->device.address);
    } else if (event->event == MSC_DEVICE_DISCONNECTED) {
        JADE_LOGI("DEVICE_DISCONNECTED");
    } else {
        return;
    }
    xQueueSend(usbstorage_msc_queue, event, portMAX_DELAY);
}

static void usbstorage_worker_impl(void* ignore)
{
    // Loop polling for USB events to process
    while (true) {
        uint32_t usb_flags = 0;
        usb_host_lib_handle_events(portMAX_DELAY, &usb_flags);
        if (usb_flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            const esp_err_t err = usb_host_device_free_all();
            if (err == ESP_OK) {
                // all devices freed already. Fall through to exit below.
                JADE_LOGI("usbstorage worker: NO_CLIENTS");
                usb_flags |= USB_HOST_LIB_EVENT_FLAGS_ALL_FREE;
            } else if (err == ESP_ERR_INVALID_STATE) {
                JADE_ASSERT_MSG(false, "usb_host_device_free_all returned ESP_ERR_INVALID_STATE");
            } else if (err != ESP_ERR_NOT_FINISHED) {
                JADE_LOGW("usb_host_device_free_all returned %d", err);
            }
        }
        if (usb_flags & USB_HOST_LIB_EVENT_FLAGS_ALL_FREE) {
            JADE_LOGI("usbstorage worker: ALL_FREE");
            break;
        }
    }
    usbstorage_state_set(USBSTATE_WORKER_SHUTDOWN);
    vTaskDelete(NULL);
}

static void usbstorage_impl(void* ignore)
{
    msc_host_device_handle_t msc_device = NULL;
    msc_host_vfs_handle_t vfs_handle = NULL;
    esp_err_t err;

    JADE_LOGI("enable_usb_host...");
    enable_usb_host();

    JADE_LOGI("usb_host_install...");
    {
        const usb_host_config_t config = { .intr_flags = ESP_INTR_FLAG_LEVEL1 };
        err = usb_host_install(&config);
    }
    JADE_LOGD("usb_host_install returned %d", err);
    usbstorage_state_set(err == ESP_OK ? USBSTATE_USB_INSTALLED : USBSTATE_ERROR);
    if (err != ESP_OK) {
        goto cleanup;
    }

    JADE_LOGI("start usb worker...");
    TaskHandle_t worker_task = NULL;
    const BaseType_t retval = xTaskCreatePinnedToCore(
        usbstorage_worker_impl, "usb_worker", 2 * 1024, NULL, JADE_TASK_PRIO_USB, &worker_task, JADE_CORE_SECONDARY);
    JADE_ASSERT(retval == pdPASS && worker_task);

    JADE_LOGI("msc_host_install..");
    {
        const msc_host_driver_config_t config = {
            .callback = msc_event_cb,
            .create_backround_task = true,
            .stack_size = 4096,
            .task_priority = JADE_TASK_PRIO_USB,
        };
        err = msc_host_install(&config);
    }
    JADE_LOGD("msc_host_install returned %d", err);
    usbstorage_state_set(err == ESP_OK ? USBSTATE_MSC_INSTALLED : USBSTATE_ERROR);
    if (err != ESP_OK) {
        goto cleanup;
    }

    // Main loop. Handle msc events, mount storage once available
    TickType_t wait_ticks = 50 / portTICK_PERIOD_MS;
    while (true) {
        msc_host_event_t ev;
        if (xQueueReceive(usbstorage_msc_queue, &ev, wait_ticks) != pdPASS) {
            if (usbstorage_state_get() & USBSTATE_SHUTDOWN_REQUESTED) {
                JADE_LOGI("usb shutdown requested");
                break;
            }
            continue;
        }
        if (ev.event == MSC_DEVICE_DISCONNECTED) {
            JADE_LOGI("DEVICE_DISCONNECTED");
            // Set the error condition even though this may not be an error
            // (e.g. if the caller has finished their processing).
            // If finished, the caller will not be checking the error state.
            usbstorage_state_set(USBSTATE_ERROR);
            break;
        } else if (ev.event == MSC_DEVICE_CONNECTED) {
            JADE_LOGI("msc_host_install_device %d..", (int)ev.device.address);
            err = msc_host_install_device(ev.device.address, &msc_device);
            JADE_LOGD("msc_host_install_device returned %d", err);
            if (err != ESP_OK) {
                usbstorage_state_set(USBSTATE_ERROR);
                break;
            }
            JADE_LOGI("msc_host_vfs_register..");
            const esp_vfs_fat_mount_config_t config = { .format_if_mount_failed = false, .max_files = 1 };
            err = msc_host_vfs_register(msc_device, USBSTORAGE_MOUNT_POINT, &config, &vfs_handle);
            JADE_LOGD("msc_host_vfs_register returned %d", err);
            if (err != ESP_OK) {
                usbstorage_state_set(USBSTATE_ERROR);
                break;
            }
            // Let the caller know that usbstorage is available, and
            // they can begin their processing.
            JADE_LOGI("notify caller task");
            xEventGroupSetBits(usbstorage_flags, USBSTORAGE_AVAILABLE);
            // Wait longer for events so the callers task has more time to run
            wait_ticks = 200 / portTICK_PERIOD_MS;
        }
    }

cleanup:
    const usbstorage_state_t state = usbstorage_state_get();
    if (state & USBSTATE_ERROR) {
        // Let the caller know an error occurred
        JADE_LOGI("post error..");
        xEventGroupSetBits(usbstorage_flags, USBSTORAGE_ERROR);
    }

    if (vfs_handle) {
        JADE_LOGI("msc_host_vfs_unregister..");
        err = msc_host_vfs_unregister(vfs_handle);
        JADE_LOGD("msc_host_vfs_unregister returned %d", err);
        vfs_handle = NULL;
    }

    if (msc_device) {
        JADE_LOGI("msc_host_uninstall_device..");
        err = msc_host_uninstall_device(msc_device);
        JADE_LOGD("msc_host_uninstall_device returned %d", err);
        msc_device = NULL;
    }

    if (state & USBSTATE_MSC_INSTALLED) {
        JADE_LOGI("msc_host_uninstall..");
        err = msc_host_uninstall();
        JADE_SEMAPHORE_TAKE(usbstorage_mutex);
        usbstorage_state &= ~USBSTATE_MSC_INSTALLED;
        JADE_SEMAPHORE_GIVE(usbstorage_mutex);
        JADE_LOGD("msc_host_uninstall returned %d", err);
    }

    if (worker_task) {
        JADE_LOGD("waiting for usb worker shutdown..");
        while (!(usbstorage_state_get() & USBSTATE_WORKER_SHUTDOWN)) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
        }
    }

    JADE_LOGI("usb_host_uninstall..");
    err = usb_host_uninstall();
    JADE_LOGD("usb_host_uninstall returned %d", err);

    JADE_LOGI("disable_usb_host");
    disable_usb_host(); // Stop powering any connected usb device

    JADE_SEMAPHORE_TAKE(usbstorage_mutex);
    // Setting usbstorage_task to NULL lets usbstorage_stop() know we are stopped
    usbstorage_task = NULL;
    JADE_SEMAPHORE_GIVE(usbstorage_mutex);

    vTaskDelete(NULL);
}

void usbstorage_init(void)
{
    JADE_ASSERT(!usbstorage_mutex && !usbstorage_flags && !usbstorage_msc_queue);
    usbstorage_mutex = xSemaphoreCreateMutex();
    usbstorage_flags = xEventGroupCreate();
    usbstorage_msc_queue = xQueueCreate(3, sizeof(msc_host_event_t));
    JADE_ASSERT(usbstorage_mutex && usbstorage_flags && usbstorage_msc_queue);
}

EventGroupHandle_t usbstorage_start(void)
{
    JADE_LOGI("usbstorage_start");
    JADE_ASSERT(usbstorage_mutex && usbstorage_flags && usbstorage_msc_queue);

    JADE_SEMAPHORE_TAKE(usbstorage_mutex);
    JADE_ASSERT(!usbstorage_task);
    usbstorage_state = USBSTATE_NONE;
    xEventGroupClearBits(usbstorage_flags, USBSTORAGE_AVAILABLE | USBSTORAGE_ERROR);

    // We must not be connected to power, i.e. USB cable
    JADE_ASSERT(!usb_is_powered());

#ifdef USBSTORAGE_DISABLE_LOGGING
    // Record initial log level and set logging to NONE
    initial_log_level = esp_log_level_get(NULL);
    esp_log_level_set("*", ESP_LOG_NONE);
#endif

    // Start up the task that brings usb storage online
    const BaseType_t retval = xTaskCreatePinnedToCore(
        usbstorage_impl, "usb_storage", 4 * 1024, NULL, JADE_TASK_PRIO_USB, &usbstorage_task, JADE_CORE_SECONDARY);
    JADE_SEMAPHORE_GIVE(usbstorage_mutex);
    JADE_ASSERT(retval == pdPASS);

    // Wait until the task has started, failed or been shutdown
    EventGroupHandle_t caller_events = NULL;
    while (true) {
        if (xSemaphoreTake(usbstorage_mutex, 10 / portTICK_PERIOD_MS) == pdTRUE) {
            if (usbstorage_state & USBSTATE_TERMINAL_EVENT) {
                break; // Failed or shutdown
            } else if (usbstorage_state & USBSTATE_USB_INSTALLED) {
                caller_events = usbstorage_flags;
                break; // Startup is underway
            }
            xSemaphoreGive(usbstorage_mutex);
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    xSemaphoreGive(usbstorage_mutex);
    return caller_events;
}

void usbstorage_stop(void)
{
    JADE_LOGI("usbstorage_stop");
    JADE_ASSERT(usbstorage_mutex && usbstorage_flags && usbstorage_msc_queue);

    // Signal usbstorage_task to shutdown/wait for it to do so
    while (true) {
        if (xSemaphoreTake(usbstorage_mutex, 10 / portTICK_PERIOD_MS) == pdTRUE) {
            if (!usbstorage_task) {
                xSemaphoreGive(usbstorage_mutex);
                break; // usbstorage_task is shutdown
            }
            usbstorage_state |= USBSTATE_SHUTDOWN_REQUESTED;
            xSemaphoreGive(usbstorage_mutex);
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

#ifdef USBSTORAGE_DISABLE_LOGGING
    // Return to initial log level
    esp_log_level_set("*", initial_log_level);
    esp_log_level_set("nvs", ESP_LOG_ERROR); // As per storage_init()
#endif
}
#endif // AMALGAMATED_BUILD
