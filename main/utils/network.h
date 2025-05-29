#ifndef UTILS_NETWORK_H_
#define UTILS_NETWORK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <network_type.h>

// Maximum length of a network name
#define MAX_NETWORK_NAME_LEN 20

bool isLiquidNetworkId(uint32_t network_id);

bool csvBlocksExpectedForNetwork(uint32_t network_id, uint32_t csvBlocks);
size_t networkToMinAllowedCsvBlocks(uint32_t network_id);

// Network name to WALLY_NETWORK_ constant, or WALLY_NETWORK_NONE if unknown
uint32_t networkToNetworkId(const char* network);
// WALLY_NETWORK_ constant to network name. Asserts if unknown/WALLY_NETWORK_NONE
const char* networkIdToNetwork(uint32_t network_id);

network_type_t networkIdToType(uint32_t network_id);
uint32_t networkToBip32Version(uint32_t network_id);

uint8_t networkToP2PKHPrefix(uint32_t network_id);
uint8_t networkToP2SHPrefix(uint32_t network_id);
const char* networkToBech32Hrp(uint32_t network_id);

// Liquid-specific
uint8_t networkToCAPrefix(uint32_t network_id);
const char* networkToBlech32Hrp(uint32_t network_id);

const char* networkGetPolicyAsset(uint32_t network_id);

#endif /* UTILS_NETWORK_H_ */
