#ifndef USBHMSC_H_
#define USBHMSC_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

#define USBSTORAGE_MOUNT_POINT "/usb"

#define USB_VISUAL_LOG false
#define USB_VISUAL_LOG_LEVEL ESP_LOG_INFO
#define USB_MESSAGE_ACTIVITY(delay, msg)                                                                               \
    do {                                                                                                               \
        if (USB_VISUAL_LOG) {                                                                                          \
            const char* message[] = { msg };                                                                           \
            display_message_activity(message, 1);                                                                      \
            vTaskDelay(delay / portTICK_PERIOD_MS);                                                                    \
        }                                                                                                              \
    } while (false)
#define USB_LOGE(delay, fmt, ...)                                                                                      \
    do {                                                                                                               \
        JADE_LOGE(fmt, ##__VA_ARGS__);                                                                                 \
        if (USB_VISUAL_LOG && USB_VISUAL_LOG_LEVEL >= ESP_LOG_ERROR) {                                                 \
            char msg[128];                                                                                             \
            snprintf(msg, sizeof(msg), fmt, ##__VA_ARGS__);                                                            \
            USB_MESSAGE_ACTIVITY(delay, msg);                                                                          \
        }                                                                                                              \
    } while (false)
#define USB_LOGI(delay, fmt, ...)                                                                                      \
    do {                                                                                                               \
        JADE_LOGI(fmt, ##__VA_ARGS__);                                                                                 \
        if (USB_VISUAL_LOG && USB_VISUAL_LOG_LEVEL >= ESP_LOG_INFO) {                                                  \
            char msg[128];                                                                                             \
            snprintf(msg, sizeof(msg), fmt, ##__VA_ARGS__);                                                            \
            USB_MESSAGE_ACTIVITY(delay, msg);                                                                          \
        }                                                                                                              \
    } while (false)

typedef enum {
    USBSTORAGE_EVENT_DETECTED,
    USBSTORAGE_EVENT_EJECTED,
    USBSTORAGE_EVENT_ABNORMALLY_EJECTED,
} usbstorage_event_t;

typedef void (*usbstorage_callback_t)(usbstorage_event_t event, uint8_t device_address, void* ctx);

/* this is required before usbstorage_start is called */
void usbstorage_register_callback(usbstorage_callback_t callback, void* ctx);

/* this is called only once in main */
void usbstorage_init(void);

/* call this any time you want to detect usb storage */
bool usbstorage_start(void);

/* this blocks until the drivers are uninstalled and tasks stopped/deleted */
void usbstorage_stop(void);

bool usbstorage_mount(uint8_t device_address);

void usbstorage_unmount(void);

#endif /* USBHMSC_H_ */
