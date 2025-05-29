#ifndef AMALGAMATED_BUILD
#include "network.h"
#include "jade_assert.h"

#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>

// Main networks
#define TAG_MAINNET "mainnet"
#define TAG_LIQUID "liquid"

// Test networks
#define TAG_TESTNET "testnet"
#define TAG_TESTNETLIQUID "testnet-liquid"
#define TAG_LOCALTEST "localtest"
#define TAG_LOCALTESTLIQUID "localtest-liquid"

// Green CSV buckets allowed
static const size_t ALLOWED_CSV_MAINNET[] = { 25920, 51840, 65535 };
static const size_t ALLOWED_CSV_TESTNET[] = { 144, 4320, 51840 };
static const size_t ALLOWED_CSV_LIQUID[] = { 65535 };
static const size_t ALLOWED_CSV_TESTNET_LIQUID[] = { 1440, 65535 };

// True for liquid and liquid regtest/testnet networks
bool isLiquidNetworkId(const uint32_t network_id)
{
    JADE_ASSERT(network_id != WALLY_NETWORK_NONE);
    return network_id == WALLY_NETWORK_LIQUID || network_id == WALLY_NETWORK_LIQUID_TESTNET
        || network_id == WALLY_NETWORK_LIQUID_REGTEST;
}

// Are the passed number of csv blocks expected for the given network
static size_t csvBlocksForNetwork(const uint32_t network_id, const size_t** csvAllowed)
{
    JADE_INIT_OUT_PPTR(csvAllowed);

    switch (network_id) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
        *csvAllowed = ALLOWED_CSV_MAINNET;
        return sizeof(ALLOWED_CSV_MAINNET) / sizeof(ALLOWED_CSV_MAINNET[0]);
    case WALLY_NETWORK_LIQUID:
        *csvAllowed = ALLOWED_CSV_LIQUID;
        return sizeof(ALLOWED_CSV_LIQUID) / sizeof(ALLOWED_CSV_LIQUID[0]);
    case WALLY_NETWORK_BITCOIN_TESTNET:
    case WALLY_NETWORK_BITCOIN_REGTEST:
        *csvAllowed = ALLOWED_CSV_TESTNET;
        return sizeof(ALLOWED_CSV_TESTNET) / sizeof(ALLOWED_CSV_TESTNET[0]);
    case WALLY_NETWORK_LIQUID_TESTNET:
    case WALLY_NETWORK_LIQUID_REGTEST:
        *csvAllowed = ALLOWED_CSV_TESTNET_LIQUID;
        return sizeof(ALLOWED_CSV_TESTNET_LIQUID) / sizeof(ALLOWED_CSV_TESTNET_LIQUID[0]);
    }
    JADE_ASSERT(false); // Unknown network
}

bool csvBlocksExpectedForNetwork(const uint32_t network_id, const uint32_t csvBlocks)
{
    const size_t* csvAllowed = NULL;
    const size_t num_allowed = csvBlocksForNetwork(network_id, &csvAllowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(csvAllowed);

    for (size_t i = 0; i < num_allowed; ++i) {
        if (csvBlocks == csvAllowed[i]) {
            return true;
        }
    }

    return false;
}

// minimum allowed csv blocks per network
size_t networkToMinAllowedCsvBlocks(const uint32_t network_id)
{
    const size_t* csvAllowed = NULL;
    const size_t num_allowed = csvBlocksForNetwork(network_id, &csvAllowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(csvAllowed);

    return csvAllowed[0];
}

uint32_t networkToNetworkId(const char* network)
{
    if (network) {
        if (!strcmp(TAG_MAINNET, network)) {
            return WALLY_NETWORK_BITCOIN_MAINNET;
        } else if (!strcmp(TAG_LIQUID, network)) {
            return WALLY_NETWORK_LIQUID;
        } else if (!strcmp(TAG_TESTNET, network)) {
            return WALLY_NETWORK_BITCOIN_TESTNET;
        } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
            return WALLY_NETWORK_LIQUID_TESTNET;
        } else if (!strcmp(TAG_LOCALTEST, network)) {
            return WALLY_NETWORK_BITCOIN_REGTEST;
        } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
            return WALLY_NETWORK_LIQUID_REGTEST;
        }
    }
    return WALLY_NETWORK_NONE;
}

const char* networkIdToNetwork(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
        return TAG_MAINNET;
    case WALLY_NETWORK_LIQUID:
        return TAG_LIQUID;
    case WALLY_NETWORK_BITCOIN_TESTNET:
        return TAG_TESTNET;
    case WALLY_NETWORK_LIQUID_TESTNET:
        return TAG_TESTNETLIQUID;
    case WALLY_NETWORK_BITCOIN_REGTEST:
        return TAG_LOCALTEST;
    case WALLY_NETWORK_LIQUID_REGTEST:
        return TAG_LOCALTESTLIQUID;
    }
    JADE_ASSERT(false);
    return NULL; // Unreachable
}

// network id to type (main or test)
network_type_t networkIdToType(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
    case WALLY_NETWORK_LIQUID:
        return NETWORK_TYPE_MAIN;
    case WALLY_NETWORK_BITCOIN_TESTNET:
    case WALLY_NETWORK_LIQUID_TESTNET:
    case WALLY_NETWORK_BITCOIN_REGTEST:
    case WALLY_NETWORK_LIQUID_REGTEST:
        return NETWORK_TYPE_TEST;
    }
    return NETWORK_TYPE_NONE;
}

// network id to BIP32 key version.
// Mainnets map to VER_MAIN_PRIVATE, testnets to VER_TEST_PRIVATE
uint32_t networkToBip32Version(const uint32_t network_id)
{
    const network_type_t network_type = networkIdToType(network_id);
    JADE_ASSERT(network_type != NETWORK_TYPE_NONE);
    return network_type == NETWORK_TYPE_MAIN ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
}

// network id to relevant P2PKH address prefix
uint8_t networkToP2PKHPrefix(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
        return WALLY_ADDRESS_VERSION_P2PKH_MAINNET;
    case WALLY_NETWORK_LIQUID:
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID;
    case WALLY_NETWORK_BITCOIN_TESTNET:
    case WALLY_NETWORK_BITCOIN_REGTEST:
        return WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
    case WALLY_NETWORK_LIQUID_TESTNET:
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET;
    case WALLY_NETWORK_LIQUID_REGTEST:
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant P2SH address prefix
uint8_t networkToP2SHPrefix(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
        return WALLY_ADDRESS_VERSION_P2SH_MAINNET;
    case WALLY_NETWORK_LIQUID:
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID;
    case WALLY_NETWORK_BITCOIN_TESTNET:
    case WALLY_NETWORK_BITCOIN_REGTEST:
        return WALLY_ADDRESS_VERSION_P2SH_TESTNET;
    case WALLY_NETWORK_LIQUID_TESTNET:
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET;
    case WALLY_NETWORK_LIQUID_REGTEST:
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant bech32 hrp
const char* networkToBech32Hrp(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
        return "bc";
    case WALLY_NETWORK_LIQUID:
        return "ex";
    case WALLY_NETWORK_BITCOIN_TESTNET:
        return "tb";
    case WALLY_NETWORK_BITCOIN_REGTEST:
        return "bcrt";
    case WALLY_NETWORK_LIQUID_TESTNET:
        return "tex";
    case WALLY_NETWORK_LIQUID_REGTEST:
        return "ert";
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return NULL; // Unreachable
}

// network id to relevant confidential address prefix
uint8_t networkToCAPrefix(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_LIQUID:
        return WALLY_CA_PREFIX_LIQUID;
    case WALLY_NETWORK_LIQUID_TESTNET:
        return WALLY_CA_PREFIX_LIQUID_TESTNET;
    case WALLY_NETWORK_LIQUID_REGTEST:
        return WALLY_CA_PREFIX_LIQUID_REGTEST;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant confidential blech32 hrp
const char* networkToBlech32Hrp(const uint32_t network_id)
{
    switch (network_id) {
    case WALLY_NETWORK_LIQUID:
        return "lq";
    case WALLY_NETWORK_LIQUID_TESTNET:
        return "tlq";
    case WALLY_NETWORK_LIQUID_REGTEST:
        return "el";
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant policy-asset (lower-case hex id)
const char* networkGetPolicyAsset(const uint32_t network_id)
{
    // These are the policy assets for the liquid networks.
    // NOTE: 'rich' information should be present in the h/coded data in assets.c
    if (network_id == WALLY_NETWORK_LIQUID) {
        return "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
    } else if (network_id == WALLY_NETWORK_LIQUID_TESTNET) {
        return "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    } else if (network_id == WALLY_NETWORK_LIQUID_REGTEST) {
        return "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
    }
    JADE_ASSERT(false); // Not a liquid network
    return NULL; // Unreachable
}
#endif // AMALGAMATED_BUILD
