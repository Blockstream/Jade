#ifndef USBHMSC_H_
#define USBHMSC_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

#define USBSTORAGE_MOUNT_POINT "/usb"

typedef enum {
    USBSTORAGE_DETECTED,
    USBSTORAGE_EJECTED,
    USBSTORAGE_ABNORMALLY_EJECTED,
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
