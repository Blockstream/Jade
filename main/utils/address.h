#ifndef UTILS_ADDRESS_H_
#define UTILS_ADDRESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_ADDRESS_LEN 128

typedef struct {
    char address[MAX_ADDRESS_LEN];
    const char* network;
    uint8_t script[MAX_ADDRESS_LEN]; // script should always be shorter than the address
    size_t script_len;
} address_data_t;

// Script pubkey to address, for BTC networks
void script_to_address(const char* network, const uint8_t* script, size_t script_len, char* output, size_t output_len);

// Script pubkey to address, for liquid networks
// Will be converted to a confidential address if blindingkey is passed.
void elements_script_to_address(const char* network, const uint8_t* script, size_t script_len,
    const uint8_t* blinding_key, size_t blinding_key_len, char* output, size_t output_len);

// Attempt to parse an address - return the network and the scriptpubkey
bool parse_address(const char* address, address_data_t* addr_data);

#endif /* UTILS_ADDRESS_H_ */
