#ifndef USBHMSC_H_
#define USBHMSC_H_

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define USBSTORAGE_MOUNT_POINT "/usb"

typedef enum {
    USBSTORAGE_AVAILABLE = 0x1,
    USBSTORAGE_ERROR = 0x2,
} usbstorage_event_t;

/* this is called only once in main */
void usbstorage_init(void);

/* Activate usb storage. If the return value is non-null, the caller will
 * be signalled when usb storage is available at USBSTORAGE_MOUNT_POINT,
 * or if an error occurs.
 */
EventGroupHandle_t usbstorage_start(void);

/* Shutdown usb storage. Blocks until the shutdown is complete */
void usbstorage_stop(void);

#endif /* USBHMSC_H_ */
