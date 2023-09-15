#ifndef USBHMSC_H_
#define USBHMSC_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdbool.h>

typedef enum {
    STORAGE_DETECTED,
    STORAGE_EJECTED,
    STORAGE_ABNORMALLY_EJECTED,
} storage_event_t;

typedef void (*storage_callback_t)(storage_event_t event, uint8_t device_address, void* ctx);

/* this is required before usb_storage_start is called */
void usb_storage_register_callback(storage_callback_t callback, void* ctx);

/* this is called only once in main */
void usb_storage_init(void);

/* call this any time you want to detect usb storage */
bool usb_storage_start(void);

/* this blocks until the drivers are uninstalled and tasks stopped/deleted */
void usb_storage_stop(void);

bool usb_storage_mount(uint8_t device_address);

void usb_storage_unmount(void);

#endif /* USBHMSC_H_ */
