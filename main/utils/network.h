#ifndef UTILS_NETWORK_H_
#define UTILS_NETWORK_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define MAX_NETWORK_NAME_LEN 20

// Main networks
#define TAG_MAINNET "mainnet"
#define TAG_LIQUID "liquid"

// Test networks
#define TAG_TESTNET "testnet"
#define TAG_TESTNETLIQUID "testnet-liquid"
#define TAG_LOCALTEST "localtest"
#define TAG_LOCALTESTLIQUID "localtest-liquid"

bool isValidNetwork(const char* network);
bool isTestNetwork(const char* network);
bool isLiquidNetwork(const char* network);

size_t csvBlocksForNetwork(const char* network, const size_t** csvAllowed);
bool csvBlocksExpectedForNetwork(const char* network, uint32_t csvBlocks);
size_t networkToMinAllowedCsvBlocks(const char* network);

uint8_t networkToId(const char* network);
uint32_t networkToVersion(const char* network);

uint8_t networkToP2PKHPrefix(const char* network);
uint8_t networkToP2SHPrefix(const char* network);
const char* networkToBech32Hrp(const char* network);

// Liquid-specific
uint8_t networkToCAPrefix(const char* network);
const char* networkToBlech32Hrp(const char* network);

bool networkUsesTestnetAssets(const char* network);
const char* networkGetPolicyAsset(const char* network);

#endif /* UTILS_NETWORK_H_ */
