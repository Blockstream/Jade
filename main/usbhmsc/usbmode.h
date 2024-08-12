#ifndef USBMODE_H_
#define USBMODE_H_

#include <stdbool.h>

// Initiate an OTA fw upgrade from compressed fw and hash file
bool usbstorage_firmware_ota(const char* extra_path);

#endif /* USBMODE_H_ */
