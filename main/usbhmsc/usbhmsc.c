#include "usbhmsc.h"

#include <esp_err.h>
#include <esp_vfs.h>
#include <esp_vfs_fat.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>
#include <msc_host.h>
#include <msc_host_vfs.h>
#include <stdlib.h>
#include <usb/usb_host.h>

#include "../jade_assert.h"
#include "../jade_log.h"
#include "../jade_tasks.h"
#include "../power.h"

#define JADE_ERROR_CHECK(x)                                                                                            \
    do {                                                                                                               \
        esp_err_t err = (x);                                                                                           \
        JADE_ASSERT(err == ESP_OK);                                                                                    \
    } while (0);

#define JADE_RETURN_CHECK(x)                                                                                           \
    do {                                                                                                               \
        esp_err_t err = (x);                                                                                           \
        if (err != ESP_OK) {                                                                                           \
            JADE_LOGE("JADE_RETURN_CHECK %d line: %d", err, __LINE__);                                                 \
            JADE_SEMAPHORE_GIVE(interface_semaphore);                                                                  \
            return false;                                                                                              \
        }                                                                                                              \
    } while (0);

typedef enum {
    HOST_NO_CLIENT = 0x1,
    HOST_ALL_FREE = 0x2,
    DEVICE_CONNECTED = 0x4,
    DEVICE_DISCONNECTED = 0x8,
    DEVICE_ADDRESS_MASK = 0xFF0,
} app_event_t;

static SemaphoreHandle_t main_task_semaphore = NULL;
static SemaphoreHandle_t aux_task_semaphore = NULL;
static SemaphoreHandle_t interface_semaphore = NULL;
static SemaphoreHandle_t callback_semaphore = NULL;
static TaskHandle_t main_task = NULL;
static bool volatile usb_is_mounted = false;

static bool volatile usbstorage_is_enabled = false;
static bool volatile usbstorage_is_enabled_subtask = false;
static EventGroupHandle_t usb_flags;

static msc_host_device_handle_t msc_device = NULL;

static msc_host_vfs_handle_t vfs_handle;

static const esp_vfs_fat_mount_config_t mount_config = {
    .format_if_mount_failed = false,
    .max_files = 1,
    .allocation_unit_size = 1024,
};

static usbstorage_callback_t registered_callback = NULL;
static void* callback_ctx = NULL;

void usbstorage_register_callback(usbstorage_callback_t callback, void* ctx)
{
    JADE_ASSERT(callback_semaphore);
    JADE_SEMAPHORE_TAKE(callback_semaphore);
    registered_callback = callback;
    callback_ctx = ctx;
    JADE_SEMAPHORE_GIVE(callback_semaphore);
}

static void trigger_event(usbstorage_event_t event, uint8_t device_address)
{
    JADE_ASSERT(callback_semaphore);
    JADE_SEMAPHORE_TAKE(callback_semaphore);
    if (registered_callback != NULL) {
        registered_callback(event, device_address, callback_ctx);
    }
    JADE_SEMAPHORE_GIVE(callback_semaphore);
}

static void msc_event_cb(const msc_host_event_t* event, void* arg)
{
    if (event->event == MSC_DEVICE_CONNECTED) {
        xEventGroupSetBits(usb_flags, DEVICE_CONNECTED | (event->device.address << 4));
    } else if (event->event == MSC_DEVICE_DISCONNECTED) {
        xEventGroupSetBits(usb_flags, DEVICE_DISCONNECTED);
    }
}

static void handle_usb_events(void* args)
{
    while (true) {
        uint32_t event_flags;
        const esp_err_t err = usb_host_lib_handle_events(100 / portTICK_PERIOD_MS, &event_flags);
        if (!usbstorage_is_enabled_subtask) {
            break;
        }
        if (err == ESP_ERR_TIMEOUT) {
            continue;
        }

        JADE_ERROR_CHECK(err);

        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            usb_host_device_free_all();
            xEventGroupSetBits(usb_flags, HOST_NO_CLIENT);
        }
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_ALL_FREE) {
            xEventGroupSetBits(usb_flags, HOST_ALL_FREE);
        }
    }

    JADE_ASSERT(!usbstorage_is_enabled);

    xSemaphoreGive(aux_task_semaphore);
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

static void usbstorage_task(void* ignore)
{

    const usb_host_config_t host_config = { .intr_flags = ESP_INTR_FLAG_LEVEL1 };
    if (usb_host_install(&host_config) != ESP_OK) {
        usbstorage_is_enabled = false;

        /* disable_usb_host(); */
        xSemaphoreGive(main_task_semaphore);
        main_task = NULL;
        vTaskDelete(NULL);
        return;
    }

    usbstorage_is_enabled_subtask = true;
    TaskHandle_t aux_task = NULL;

    usb_flags = xEventGroupCreate();
    JADE_ASSERT(usb_flags);

    const BaseType_t task_created = xTaskCreatePinnedToCore(
        handle_usb_events, "usb_events", 1024, NULL, JADE_TASK_PRIO_USB, &aux_task, JADE_CORE_SECONDARY);
    JADE_ASSERT(task_created == pdPASS);
    JADE_ASSERT(aux_task);

    const msc_host_driver_config_t msc_config = {
        .create_backround_task = true,
        .task_priority = 5,
        .core_id = JADE_CORE_SECONDARY,
        .stack_size = 2048 * 2,
        .callback = msc_event_cb,
    };

    JADE_ERROR_CHECK(msc_host_install(&msc_config));

    bool done = false;

    /* signal to usbstorage_start that we completed the start without [major] fail */
    xSemaphoreGive(main_task_semaphore);

    bool requires_host_uinstall = true;
    while (!done) {
        const TickType_t xTicksToWait = 100 / portTICK_PERIOD_MS;

        const EventBits_t event
            = xEventGroupWaitBits(usb_flags, DEVICE_CONNECTED | DEVICE_ADDRESS_MASK, pdTRUE, pdFALSE, xTicksToWait);

        if (!usbstorage_is_enabled) {
            break;
        }

        if (!(event & (DEVICE_CONNECTED | DEVICE_ADDRESS_MASK))) {
            continue;
        }

        const uint8_t device_address = (event & DEVICE_ADDRESS_MASK) >> 4;
        trigger_event(USBSTORAGE_EVENT_DETECTED, device_address);
        for (;;) {
            const EventBits_t ebt = xEventGroupWaitBits(usb_flags, 0xFF, pdTRUE, pdFALSE, xTicksToWait);
            if (ebt & HOST_ALL_FREE) {
                // user removed the device which wasn't mounted
                trigger_event(USBSTORAGE_EVENT_EJECTED, device_address);
                done = !usbstorage_is_enabled;
                break;
            } else if (ebt & DEVICE_DISCONNECTED) {
                // user removed the device which was mounted!
                trigger_event(USBSTORAGE_EVENT_ABNORMALLY_EJECTED, device_address);
                done = !usbstorage_is_enabled;
                break;
            } else if (ebt & (DEVICE_CONNECTED | HOST_ALL_FREE)) {
                trigger_event(USBSTORAGE_EVENT_EJECTED, device_address);
                done = !usbstorage_is_enabled;
                break;
            } else if (!ebt && requires_host_uinstall && !usb_is_mounted) {
                esp_err_t err = msc_host_uninstall();
                JADE_ASSERT(err == ESP_OK);
                requires_host_uinstall = false;
            }
        }
    }
    registered_callback = NULL;
    callback_ctx = NULL;

    // This may fail if the user removes the device at the right time
    if (requires_host_uinstall) {
        const esp_err_t err = msc_host_uninstall();
        if (err != ESP_OK) {
            JADE_LOGE("msc_host_uninstall failed %d", err);
        }
    }

    usbstorage_is_enabled_subtask = false;
    xSemaphoreTake(aux_task_semaphore, portMAX_DELAY);
    vTaskDelete(aux_task);
    vEventGroupDelete(usb_flags);

    const esp_err_t err = usb_host_uninstall();
    if (err != ESP_OK) {
        JADE_LOGE("usb_host_uninstall failed %d", err);
    }

    xSemaphoreGive(main_task_semaphore);

    // wait to be killed
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

void usbstorage_init(void)
{
    JADE_ASSERT(!main_task_semaphore);
    JADE_ASSERT(!aux_task_semaphore);
    JADE_ASSERT(!interface_semaphore);
    JADE_ASSERT(!callback_semaphore);
    main_task_semaphore = xSemaphoreCreateBinary();
    aux_task_semaphore = xSemaphoreCreateBinary();
    interface_semaphore = xSemaphoreCreateMutex();
    callback_semaphore = xSemaphoreCreateMutex();
    JADE_ASSERT(main_task_semaphore);
    JADE_ASSERT(aux_task_semaphore);
    JADE_ASSERT(interface_semaphore);
    JADE_ASSERT(callback_semaphore);
}

bool usbstorage_start(void)
{
    JADE_ASSERT(main_task_semaphore);
    JADE_ASSERT(aux_task_semaphore);
    JADE_ASSERT(interface_semaphore);
    JADE_SEMAPHORE_TAKE(interface_semaphore);
    JADE_ASSERT(!usbstorage_is_enabled);
    JADE_ASSERT(!main_task);

    // Power any connected device
    JADE_ASSERT(!usb_connected());
    enable_usb_host();

    usbstorage_is_enabled = true;
    const BaseType_t task_created = xTaskCreatePinnedToCore(
        usbstorage_task, "usb_storage", 2 * 1024, NULL, JADE_TASK_PRIO_USB, &main_task, JADE_CORE_SECONDARY);
    JADE_ASSERT(task_created == pdPASS);
    JADE_ASSERT(main_task);
    xSemaphoreTake(main_task_semaphore, portMAX_DELAY);
    const bool enabled = usbstorage_is_enabled;
    JADE_SEMAPHORE_GIVE(interface_semaphore);
    return enabled;
}

void usbstorage_stop(void)
{
    JADE_ASSERT(main_task);
    JADE_SEMAPHORE_TAKE(interface_semaphore);
    JADE_ASSERT(usbstorage_is_enabled);
    usbstorage_is_enabled = false;
    xSemaphoreTake(main_task_semaphore, portMAX_DELAY);

    vTaskDelete(main_task);
    main_task = NULL;

    // Stop powering any connected usb device
    disable_usb_host();

    JADE_SEMAPHORE_GIVE(interface_semaphore);
}

bool usbstorage_mount(uint8_t device_address)
{
    JADE_SEMAPHORE_TAKE(interface_semaphore);
    /* if any of these fails usually is because the device was removed */
    JADE_RETURN_CHECK(msc_host_install_device(device_address, &msc_device));
    JADE_RETURN_CHECK(msc_host_vfs_register(msc_device, USBSTORAGE_MOUNT_POINT, &mount_config, &vfs_handle));
    usb_is_mounted = true;
    JADE_SEMAPHORE_GIVE(interface_semaphore);
    return true;
}

void usbstorage_unmount(void)
{
    JADE_SEMAPHORE_TAKE(interface_semaphore);
    // FIXME: on failure just send a callback rather than ERROR_CHECK?
    JADE_ERROR_CHECK(msc_host_vfs_unregister(vfs_handle));
    JADE_ERROR_CHECK(msc_host_uninstall_device(msc_device));
    usb_is_mounted = false;
    JADE_SEMAPHORE_GIVE(interface_semaphore);
}
