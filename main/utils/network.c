#include "network.h"
#include "jade_assert.h"

#include <wally_address.h>
#include <wally_bip32.h>

// True for known networks
bool isValidNetwork(const char* network)
{
    if (!network) {
        return false;
    }
    return !strcmp(TAG_MAINNET, network) || !strcmp(TAG_LIQUID, network) || !strcmp(TAG_TESTNET, network)
        || !strcmp(TAG_TESTNETLIQUID, network) || !strcmp(TAG_LOCALTEST, network)
        || !strcmp(TAG_LOCALTESTLIQUID, network);
}

// True for testnet and localtest type networks
bool isTestNetwork(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));
    return !strcmp(TAG_TESTNET, network) || !strcmp(TAG_TESTNETLIQUID, network) || !strcmp(TAG_LOCALTEST, network)
        || !strcmp(TAG_LOCALTESTLIQUID, network);
}

// True for liquid and localtestliquid networks
bool isLiquidNetwork(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));
    return !strcmp(TAG_LIQUID, network) || !strcmp(TAG_TESTNETLIQUID, network) || !strcmp(TAG_LOCALTESTLIQUID, network);
}

// Are the passed number of csv blocks expected for the given network
bool csvBlocksExpectedForNetwork(const char* network, const uint32_t csvBlocks)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network)) {
        return csvBlocks == 25920 || csvBlocks == 51840 || csvBlocks == 65535;
    } else if (!strcmp(TAG_LIQUID, network)) {
        return csvBlocks == 65535;
    } else if (!strcmp(TAG_TESTNET, network) || !strcmp(TAG_LOCALTEST, network)) {
        return csvBlocks == 144 || csvBlocks == 4320 || csvBlocks == 51840;
    } else if (!strcmp(TAG_TESTNETLIQUID, network) || !strcmp(TAG_LOCALTESTLIQUID, network)) {
        return csvBlocks == 1440 || csvBlocks == 65535;
    } else {
        return false;
    }
}

// minimum allowed csv blocks per network
size_t networkToMinAllowedCsvBlocks(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network)) {
        return 25920;
    } else if (!strcmp(TAG_LIQUID, network)) {
        return 65535;
    } else if (!strcmp(TAG_TESTNET, network) || !strcmp(TAG_LOCALTEST, network)) {
        return 144;
    } else if (!strcmp(TAG_TESTNETLIQUID, network) || !strcmp(TAG_LOCALTESTLIQUID, network)) {
        return 1440;
    } else {
        return SIZE_MAX;
    }
}

// 'mainnet' and 'liquid' map to VER_MAIN_PRIVATE, others to VER_TEST_PRIVATE
uint32_t networkToVersion(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network) || !strcmp(TAG_LIQUID, network)) {
        return BIP32_VER_MAIN_PRIVATE;
    } else if (isTestNetwork(network)) {
        return BIP32_VER_TEST_PRIVATE;
    } else {
        return 0;
    }
}

// 'mainnet' like string to relevant P2PKH address prefix
uint8_t networkToP2PKHPrefix(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network)) {
        return WALLY_ADDRESS_VERSION_P2PKH_MAINNET;
    } else if (!strcmp(TAG_TESTNET, network) || !strcmp(TAG_LOCALTEST, network)) {
        return WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
    } else if (!strcmp(TAG_LIQUID, network)) {
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID;
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET;
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST;
    } else {
        return 0;
    }
}

// 'mainnet' like string to relevant P2SH address prefix
uint8_t networkToP2SHPrefix(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network)) {
        return WALLY_ADDRESS_VERSION_P2SH_MAINNET;
    } else if (!strcmp(TAG_TESTNET, network) || !strcmp(TAG_LOCALTEST, network)) {
        return WALLY_ADDRESS_VERSION_P2SH_TESTNET;
    } else if (!strcmp(TAG_LIQUID, network)) {
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID;
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET;
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST;
    } else {
        return 0;
    }
}

// 'liquid' like string to relevant confidential address prefix
uint8_t networkToCAPrefix(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_LIQUID, network)) {
        return WALLY_CA_PREFIX_LIQUID;
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return WALLY_CA_PREFIX_LIQUID_TESTNET;
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return WALLY_CA_PREFIX_LIQUID_REGTEST;
    } else {
        return 0;
    }
}

// 'mainnet' like string to relevant bech32 hrp
const char* networkToBech32Hrp(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network)) {
        return "bc";
    } else if (!strcmp(TAG_TESTNET, network)) {
        return "tb";
    } else if (!strcmp(TAG_LOCALTEST, network)) {
        return "bcrt";
    } else if (!strcmp(TAG_LIQUID, network)) {
        return "ex";
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return "tex";
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return "ert";
    } else {
        return NULL;
    }
}

// 'liquid' like string to relevant confidential blech32 hrp
const char* networkToBlech32Hrp(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_LIQUID, network)) {
        return "lq";
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return "tlq";
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return "el";
    } else {
        return NULL;
    }
}
