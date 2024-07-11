#ifndef USBMODE_H_
#define USBMODE_H_

#include <stdbool.h>

// List files for firmware flashing and start the client task to feed the data to the ota process
bool usbmode_start_ota(const char* const path);

#endif /* USBMODE_H_ */
