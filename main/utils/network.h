#ifndef UTILS_NETWORK_H_
#define UTILS_NETWORK_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <network_type.h>

#define MAX_NETWORK_NAME_LEN 20

// Main networks
#define TAG_MAINNET "mainnet"
#define TAG_LIQUID "liquid"

// Test networks
#define TAG_TESTNET "testnet"
#define TAG_TESTNETLIQUID "testnet-liquid"
#define TAG_LOCALTEST "localtest"
#define TAG_LOCALTESTLIQUID "localtest-liquid"

bool isLiquidNetworkId(const uint32_t network_id);

bool csvBlocksExpectedForNetwork(const uint32_t network_id, uint32_t csvBlocks);
size_t networkToMinAllowedCsvBlocks(const uint32_t network_id);

// TAG_ string to WALLY_NETWORK_ constant, or WALLY_NETWORK_NONE if unknown
uint32_t networkToNetworkId(const char* network);
// WALLY_NETWORK_ constant to TAG_ string. Asserts if unknown/WALLY_NETWORK_NONE
const char* networkIdToNetwork(const uint32_t network_id);

network_type_t networkIdToType(const uint32_t network_id);
uint32_t networkToBip32Version(const uint32_t network_id);

uint8_t networkToP2PKHPrefix(const uint32_t network_id);
uint8_t networkToP2SHPrefix(const uint32_t network_id);
const char* networkToBech32Hrp(const uint32_t network_id);

// Liquid-specific
uint8_t networkToCAPrefix(const uint32_t network_id);
const char* networkToBlech32Hrp(const uint32_t network_id);

const char* networkGetPolicyAsset(const uint32_t network_id);

#endif /* UTILS_NETWORK_H_ */
