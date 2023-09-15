#ifndef USBMODE_H_
#define USBMODE_H_

#include <stdbool.h>

/* This list files for firmware flashing but also optionally starts a task to feed the data to the ota task */
bool list_files(const char* const path);

#endif /* USBMODE_H_ */
