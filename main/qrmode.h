#ifndef QRMODE_H_
#define QRMODE_H_

#include <stdbool.h>

// Display singlesig xpub qr code
void display_xpub_qr(void);

// Scan an address qr and verify by brute-forcing
bool scan_verify_address_qr(void);

// Scan a PSBT, attempt to sign it, and display the resultant PSBT QR
bool scan_sign_display_psbt_qr(void);

// Display screen with help url and qr code
void display_qr_help_screen(const char* url);

#endif /* QRMODE_H_ */
