#ifndef UTILS_NETWORK_H_
#define UTILS_NETWORK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <network_type.h>

// Maximum length of a network name
#define MAX_NETWORK_NAME_LEN 20

bool network_is_liquid(uint32_t network_id);

bool network_is_known_csv_blocks(uint32_t network_id, uint32_t csv_blocks);
bool network_is_allowable_csv_blocks(uint32_t network_id, uint32_t csv_blocks);

// Network name to WALLY_NETWORK_ constant, or WALLY_NETWORK_NONE if unknown
uint32_t network_from_name(const char* network);
// WALLY_NETWORK_ constant to network name. Asserts if unknown/WALLY_NETWORK_NONE
const char* network_to_name(uint32_t network_id);

network_type_t network_to_type(uint32_t network_id);
uint32_t network_to_bip32_version(uint32_t network_id);

uint8_t network_to_p2pkh_prefix(uint32_t network_id);
uint8_t network_to_p2sh_prefix(uint32_t network_id);
const char* network_to_bech32_prefix(uint32_t network_id);

// Liquid-specific
uint8_t network_to_confidential_prefix(uint32_t network_id);
const char* network_to_blech32_prefix(uint32_t network_id);

const char* network_to_policy_asset_hex(uint32_t network_id);

#endif /* UTILS_NETWORK_H_ */
