#ifndef UTILS_NETWORK_H_
#define UTILS_NETWORK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <network_type.h>

// Maximum length of a network name
#define MAX_NETWORK_NAME_LEN 20

// Network ID - values are set to match wally constants
typedef enum {
    NETWORK_NONE = 0x00,
    NETWORK_BITCOIN = 0x01,
    NETWORK_BITCOIN_REGTEST = 0xff,
    NETWORK_BITCOIN_TESTNET = 0x02,
    NETWORK_LIQUID = 0x03,
    NETWORK_LIQUID_REGTEST = 0x04,
    NETWORK_LIQUID_TESTNET = 0x05
} network_t;

bool network_is_liquid(uint32_t network_id);

bool network_is_known_csv_blocks(uint32_t network_id, uint32_t csv_blocks);
bool network_is_allowable_csv_blocks(uint32_t network_id, uint32_t csv_blocks);

// Network name to NETWORK_ constant, or NETWORK_NONE if unknown
uint32_t network_from_name(const char* name);
// NETWORK_ constant to network name. Asserts if unknown/NETWORK_NONE
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
