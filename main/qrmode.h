#ifndef QRMODE_H_
#define QRMODE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Display singlesig xpub qr code
void display_xpub_qr(void);

// Handle scanning a QR - supports addresses and PSBTs
void handle_scan_qr(void);

// Display a BC-UR bytes message
bool display_bcur_bytes_qr(const char* label, const uint8_t* data, size_t data_len, const char* help_url);

// Display screen with single arbitrary qr code
// Handles up to v6 codes - ie. text up to 134 bytes
// help_url is optional
void await_single_qr_activity(const char* label, const uint8_t* data, size_t data_len, const char* help_url);

// Display screen with help url and qr code
void await_qr_help_activity(const char* url);

// Display screen with label, url, qr code, and back/continue buttons
bool await_qr_back_continue_activity(const char* label, const char* url, bool default_selection);

// Start pinserver authentication via qr codes
void handle_qr_auth(void);

#endif /* QRMODE_H_ */
