#ifndef QRMODE_H_
#define QRMODE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cbor.h>

#include "otpauth.h"

// NOTE: Jade only supports the bip39 English wordlist,
// with a 12 or 24 word mnemonic phrase.
#define MNEMONIC_MAXWORDS 24

// The longest valid words in the English wordlist are 8 characters.
#define MNEMONIC_MAX_WORD_LEN 8

// Size of a buffer for holding a mnemonic phrase.
// 24 8-character words + 23 spaces + NUL = 216 bytes
#define MNEMONIC_BUFLEN 216

// Display singlesig xpub qr code
void display_xpub_qr(void);

// Handle scanning a QR - supports addresses and PSBTs
void handle_scan_qr(void);

// Display a BC-UR bytes message
bool display_bcur_bytes_qr(
    const char* message[], size_t message_size, const uint8_t* data, size_t data_len, const char* help_url);

// Display bip85/bip39 encrypted entropy as BC-UR QR.
void show_bip85_bip39_entropy_qr(const uint8_t* cbor, const size_t cbor_len);

// Display screen with qr code
// Handles up to v6. codes - ie text up to 134 bytes
void await_single_qr_activity(const char* message[], size_t message_size, const uint8_t* data, size_t data_len);

// Display screen with help url and qr code
void await_qr_help_activity(const char* url);

// Display screen with label, url, qr code, and back/continue buttons
bool await_qr_back_continue_activity(
    const char* message[], size_t message_size, const char* url, bool default_selection);

// Display a QR code for the OTP context
bool show_otp_uri_qr_activity(const otpauth_ctx_t* otp_ctx);

// Start pinserver authentication via qr codes
void handle_qr_auth(bool suppress_pin_change_confirmation);

#endif /* QRMODE_H_ */
