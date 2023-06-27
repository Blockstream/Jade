#ifndef BCUR_H_
#define BCUR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tft.h>

#include "utils/cbor_rpc.h"
#include "wallet.h"

struct wally_psbt;

// Some BC-UR 'type' strings
extern const char BCUR_TYPE_CRYPTO_BIP39[];
extern const char BCUR_TYPE_CRYPTO_ACCOUNT[];
extern const char BCUR_TYPE_CRYPTO_HDKEY[];
extern const char BCUR_TYPE_CRYPTO_PSBT[];
extern const char BCUR_TYPE_JADE_PIN[];
extern const char BCUR_TYPE_JADE_EPOCH[];
extern const char BCUR_TYPE_JADE_UPDPS[];
extern const char BCUR_TYPE_BYTES[];

// Parse BC-UR messages - decodes BC-UR and parses nested CBOR
bool bcur_parse_bip39_wrapper(const char* bcur, size_t bcur_len, char* mnemonic, size_t mnemonic_len, size_t* written);
bool bcur_parse_bip39(const uint8_t* cbor, size_t cbor_len, char* mnemonic, size_t mnemonic_len, size_t* written);
bool bcur_parse_bytes(const uint8_t* cbor, size_t cbor_len, const uint8_t** bytes, size_t* bytes_len);
bool bcur_parse_psbt(const uint8_t* cbor, size_t cbor_len, struct wally_psbt** psbt_out);
bool bcur_parse_jade_message(const uint8_t* cbor, size_t cbor_len, CborParser* parser, CborValue* root,
    const char* expected_method, CborValue* params);

// Build BC-UR CBOR messages
void bcur_build_cbor_crypto_hdkey(
    const uint32_t* path, size_t path_len, uint8_t* output, size_t output_len, size_t* written);
void bcur_build_cbor_crypto_account(script_variant_t script_variant, const uint32_t* path, size_t path_len,
    uint8_t* output, size_t output_len, size_t* written);
bool bcur_build_cbor_crypto_psbt(const struct wally_psbt* psbt, uint8_t** output, size_t* output_len);

// Scan a QR code that may be a BC-UR code/fragment - ie. single-frame or animated/multi-frame.
// Returns true if a complete (ie. potentially multi-frame) bc-ur code is scanned, or if a single
// non-BC-UR frame is scanned successfully.
// If BC-UR, the complete scanned payload and its BC-UR 'type' are returned.
// NOTE: output is expected to be a valid CBOR message, although this is not validated.
// If not BC-UR, the scanned payload is returned with a type of NULL.
// In either case the caller takes ownership, and must free the output data bytes and any type string.
// Returns false if scanning fails or is abandoned - in which case there is nothing to free.
bool bcur_scan_qr(
    const char* prompt_text, char** output_type, uint8_t** output, size_t* output_len, const char* help_url);

// Encodes the passed payload into a set of one or more BC-UR fragments with the given 'type'.
// These are then rendered as a set of QR codes of the passed version/size.
// NOTE: input is expected to be a valid CBOR message, although this is not validated
// Caller takes ownership of the icons returned.
void bcur_create_qr_icons(
    const uint8_t* payload, size_t len, const char* bcur_type, uint8_t qr_version, Icon** icons, size_t* num_icons);

#endif /* BCUR_H_ */
