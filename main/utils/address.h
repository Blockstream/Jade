#ifndef UTILS_ADDRESS_H_
#define UTILS_ADDRESS_H_

// TODO: Confirm maximum address length
#define MAX_ADDRESS_LEN 128

// Script pubkey to address, for BTC networks
void script_to_address(const char* network, uint8_t* script, size_t script_len, char* output, size_t output_len);

// Script pubkey to address, for liquid networks
// Will be converted to a confidential address if blindingkey is passed.
void elements_script_to_address(const char* network, uint8_t* script, size_t script_len, const uint8_t* blinding_key,
    size_t blinding_key_len, char* output, size_t output_len);

#endif /* UTILS_ADDRESS_H_ */
