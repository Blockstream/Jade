#ifndef QRMODE_H_
#define QRMODE_H_

#include <stdbool.h>

// Display singlesig xpub qr code
void display_xpub_qr(void);

// Handle scanning a QR - supports addresses and PSBTs
void handle_scan_qr(void);

// Display screen with help url and qr code
void display_qr_help_screen(const char* url);

#endif /* QRMODE_H_ */
