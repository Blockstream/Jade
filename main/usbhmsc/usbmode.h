#ifndef USBMODE_H_
#define USBMODE_H_

#include <stdbool.h>

// Initiate an OTA fw upgrade from compressed fw and hash file
bool usbstorage_firmware_ota(const char* extra_path);

// Sign PSBT file, and write updated file
bool usbstorage_sign_psbt(const char* extra_path);
// Write xpub file to usb
bool usbstorage_export_xpub(const char* extra_path);


#endif /* USBMODE_H_ */
