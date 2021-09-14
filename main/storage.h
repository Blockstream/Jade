#ifndef STORAGE_H_
#define STORAGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { NETWORK_TYPE_NONE, NETWORK_TYPE_MAIN, NETWORK_TYPE_TEST } network_type_t;

#define BLE_ENABLED 0x1

#define MAX_PINSVR_CERTIFICATE_LENGTH 2048
#define MAX_PINSVR_URL_LENGTH 120

bool storage_init(void);
bool storage_erase(void);
bool storage_get_stats(size_t* entries_used, size_t* entries_free);

bool storage_set_pin_privatekey(const unsigned char* privatekey, size_t key_len);
bool storage_get_pin_privatekey(unsigned char* privatekey, size_t key_len);
bool storage_erase_pin_privatekey(void);

bool storage_set_encrypted_blob(const unsigned char* encrypted, size_t encrypted_len);
bool storage_get_encrypted_blob(unsigned char* encrypted, size_t encrypted_len);
bool storage_decrement_counter(void);
bool storage_restore_counter(void);
uint8_t storage_get_counter(void);
bool storage_erase_encrypted_blob(void);

bool storage_set_pinserver_details(const char* urlA, const char* urlB, const unsigned char* pubkey, size_t pubkey_len);
bool storage_get_pinserver_urlA(char* url, size_t len, size_t* written);
bool storage_get_pinserver_urlB(char* url, size_t len, size_t* written);
bool storage_get_pinserver_pubkey(unsigned char* pubkey, size_t pubkey_len);
bool storage_erase_pinserver_details(void);

bool storage_set_pinserver_cert(const char* cert);
bool storage_get_pinserver_cert(char* cert, size_t len, size_t* written);
bool storage_erase_pinserver_cert(void);

bool storage_set_network_type_restriction(network_type_t networktype);
network_type_t storage_get_network_type_restriction(void);

bool storage_set_idle_timeout(uint16_t timeout);
uint16_t storage_get_idle_timeout(void);

bool storage_set_click_event(uint8_t event);
uint8_t storage_get_click_event(void);

bool storage_set_ble_flags(uint8_t flags);
uint8_t storage_get_ble_flags(void);

#endif /* STORAGE_H_ */
