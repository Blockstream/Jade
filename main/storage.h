#ifndef STORAGE_H_
#define STORAGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <nvs.h>

#include <network_type.h>

#define BLE_ENABLED 0x1

#define GUI_FLAGS_THEMES_MASK 0x7
#define GUI_FLAGS_FLIP_ORIENTATION 0x40
#define GUI_FLAGS_USE_WHEEL_CLICK 0x80

#define QR_DENSITY_LOW 0x1
#define QR_DENSITY_HIGH 0x2
#define QR_SPEED_LOW 0x4
#define QR_SPEED_HIGH 0x8

#define QR_XPUB_WITNESS 0x100
#define QR_XPUB_MULTISIG 0x200
#define QR_XPUB_HDKEY 0x400
#define QR_XPUB_LEGACY 0x800

#define KEY_FLAGS_AUTO_DEFAULT_PASSPHRASE 0x1
#define KEY_FLAGS_USER_TO_ENTER_PASSPHRASE 0x2
#define KEY_FLAGS_WORDLIST_PASSPHRASE 0x4
#define KEY_FLAGS_CONFIRM_EXPORT_BLINDING_KEY 0x80

#define MAX_PINSVR_CERTIFICATE_LENGTH 2048
#define MAX_PINSVR_URL_LENGTH 120

bool storage_init(void);
bool storage_erase(void);
bool storage_get_stats(size_t* entries_used, size_t* entries_free);
bool storage_key_name_valid(const char* name);

bool storage_set_pin_privatekey(const uint8_t* privatekey, size_t key_len);
bool storage_get_pin_privatekey(uint8_t* privatekey, size_t key_len);
bool storage_erase_pin_privatekey(void);

bool storage_set_encrypted_blob(const uint8_t* encrypted, size_t encrypted_len);
bool storage_get_encrypted_blob(uint8_t* encrypted, size_t encrypted_len, size_t* written);
bool storage_decrement_counter(void);
bool storage_restore_counter(void);
uint8_t storage_get_counter(void);
bool storage_get_replay_counter(uint8_t* replay_counter);
bool storage_erase_encrypted_blob(void);

bool storage_set_key_flags(uint8_t flags);
uint8_t storage_get_key_flags(void);

bool storage_set_wallet_erase_pin(const uint8_t* pin, size_t pin_len);
bool storage_get_wallet_erase_pin(uint8_t* pin, size_t pin_len);
bool storage_erase_wallet_erase_pin(void);

bool storage_set_pinserver_details(const char* urlA, const char* urlB, const uint8_t* pubkey, size_t pubkey_len);
bool storage_get_pinserver_urlA(char* url, size_t len, size_t* written);
bool storage_get_pinserver_urlB(char* url, size_t len, size_t* written);
bool storage_get_pinserver_pubkey(uint8_t* pubkey, size_t pubkey_len);
bool storage_erase_pinserver_details(void);

bool storage_set_pinserver_cert(const char* cert);
bool storage_get_pinserver_cert(char* cert, size_t len, size_t* written);
bool storage_erase_pinserver_cert(void);

bool storage_set_network_type_restriction(network_type_t networktype);
network_type_t storage_get_network_type_restriction(void);

bool storage_set_idle_timeout(uint16_t timeout);
uint16_t storage_get_idle_timeout(void);

bool storage_set_brightness(uint8_t brightness);
uint8_t storage_get_brightness(void);

bool storage_set_gui_flags(uint8_t color);
uint8_t storage_get_gui_flags(void);

bool storage_set_custom_theme_color(uint16_t color);
uint16_t storage_get_custom_theme_color(void);

bool storage_set_ble_flags(uint8_t flags);
uint8_t storage_get_ble_flags(void);

bool storage_set_qr_flags(uint32_t flags);
uint32_t storage_get_qr_flags(void);

// Generic multisig
bool storage_set_multisig_registration(const char* name, const uint8_t* registration, size_t registration_len);
bool storage_get_multisig_registration(
    const char* name, uint8_t* registration, size_t registration_len, size_t* written);

size_t storage_get_multisig_registration_count(void);
bool storage_multisig_name_exists(const char* name);
bool storage_get_all_multisig_registration_names(
    char names[][NVS_KEY_NAME_MAX_SIZE], size_t num_names, size_t* num_written);

bool storage_erase_multisig_registration(const char* name);

// Descriptor wallets
bool storage_set_descriptor_registration(const char* name, const uint8_t* registration, size_t registration_len);
bool storage_get_descriptor_registration(
    const char* name, uint8_t* registration, size_t registration_len, size_t* written);

size_t storage_get_descriptor_registration_count(void);
bool storage_descriptor_name_exists(const char* name);
bool storage_get_all_descriptor_registration_names(
    char names[][NVS_KEY_NAME_MAX_SIZE], size_t num_names, size_t* num_written);

bool storage_erase_descriptor_registration(const char* name);

// HOTP / TOTP
bool storage_set_otp_data(const char* name, const uint8_t* data, size_t data_len);
bool storage_get_otp_data(const char* name, uint8_t* data, size_t data_len, size_t* written);

bool storage_set_otp_hotp_counter(const char* name, const uint64_t counter);
uint64_t storage_get_otp_hotp_counter(const char* name);

size_t storage_get_otp_count(void);
bool storage_otp_exists(const char* name);
bool storage_get_all_otp_names(char names[][NVS_KEY_NAME_MAX_SIZE], size_t num_names, size_t* num_written);

bool storage_erase_otp(const char* name);

#endif /* STORAGE_H_ */
