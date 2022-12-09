#ifndef QRMODE_H_
#define QRMODE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Display singlesig xpub qr code
void display_xpub_qr(void);

// Handle scanning a QR - supports addresses and PSBTs
void handle_scan_qr(void);

// Display screen with single arbitrary qr code
// Handles up to v6 codes - ie. text up to 134 bytes
void await_single_qr_activity(const char* title, const char* label, const uint8_t* data, size_t data_len);

// Display screen with help url and qr code
void await_qr_help_activity(const char* url);

#endif /* QRMODE_H_ */
