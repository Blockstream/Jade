#ifndef AMALGAMATED_BUILD
#include "network.h"
#include "jade_assert.h"

#include <wally_address.h>
#include <wally_bip32.h>

// Green CSV buckets allowed
static const size_t ALLOWED_CSV_MAINNET[] = { 25920, 51840, 65535 };
static const size_t ALLOWED_CSV_TESTNET[] = { 144, 4320, 51840 };
static const size_t ALLOWED_CSV_LIQUID[] = { 65535 };
static const size_t ALLOWED_CSV_TESTNET_LIQUID[] = { 1440, 65535 };

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
size_t csvBlocksForNetwork(const char* network, const size_t** csvAllowed)
{
    JADE_ASSERT(isValidNetwork(network));
    JADE_INIT_OUT_PPTR(csvAllowed);

    if (!strcmp(TAG_MAINNET, network)) {
        *csvAllowed = ALLOWED_CSV_MAINNET;
        return sizeof(ALLOWED_CSV_MAINNET) / sizeof(ALLOWED_CSV_MAINNET[0]);
    } else if (!strcmp(TAG_LIQUID, network)) {
        *csvAllowed = ALLOWED_CSV_LIQUID;
        return sizeof(ALLOWED_CSV_LIQUID) / sizeof(ALLOWED_CSV_LIQUID[0]);
    } else if (!strcmp(TAG_TESTNET, network) || !strcmp(TAG_LOCALTEST, network)) {
        *csvAllowed = ALLOWED_CSV_TESTNET;
        return sizeof(ALLOWED_CSV_TESTNET) / sizeof(ALLOWED_CSV_TESTNET[0]);
    } else if (!strcmp(TAG_TESTNETLIQUID, network) || !strcmp(TAG_LOCALTESTLIQUID, network)) {
        *csvAllowed = ALLOWED_CSV_TESTNET_LIQUID;
        return sizeof(ALLOWED_CSV_TESTNET_LIQUID) / sizeof(ALLOWED_CSV_TESTNET_LIQUID[0]);
    } else {
        *csvAllowed = NULL;
        return 0;
    }
}

bool csvBlocksExpectedForNetwork(const char* network, const uint32_t csvBlocks)
{
    JADE_ASSERT(network);

    const size_t* csvAllowed = NULL;
    const size_t num_allowed = csvBlocksForNetwork(network, &csvAllowed);
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
size_t networkToMinAllowedCsvBlocks(const char* network)
{
    JADE_ASSERT(network);

    const size_t* csvAllowed = NULL;
    const size_t num_allowed = csvBlocksForNetwork(network, &csvAllowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(csvAllowed);

    return csvAllowed[0];
}

// Network string to wally's network id value
uint8_t networkToId(const char* network)
{
    JADE_ASSERT(isValidNetwork(network));

    if (!strcmp(TAG_MAINNET, network)) {
        return WALLY_NETWORK_BITCOIN_MAINNET;
    } else if (!strcmp(TAG_TESTNET, network) || !strcmp(TAG_LOCALTEST, network)) {
        return WALLY_NETWORK_BITCOIN_TESTNET;
    } else if (!strcmp(TAG_LIQUID, network)) {
        return WALLY_NETWORK_LIQUID;
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return WALLY_NETWORK_LIQUID_TESTNET;
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return WALLY_NETWORK_LIQUID_REGTEST;
    } else {
        return 0;
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

// 'liquid' like string to relevant confidential address prefix
uint8_t networkToCAPrefix(const char* network)
{
    JADE_ASSERT(isLiquidNetwork(network));

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

// 'liquid' like string to relevant confidential blech32 hrp
const char* networkToBlech32Hrp(const char* network)
{
    JADE_ASSERT(isLiquidNetwork(network));

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

/* FIXME: Remove this if/when TAG_LOCALTESTLIQUID uses testnet assets */
bool networkUsesTestnetAssets(const char* network)
{
    JADE_ASSERT(isLiquidNetwork(network));

    // TAG_LOCALTESTLIQUID appears to use mainnet assets ?
    return !strcmp(TAG_TESTNETLIQUID, network);
}

// hexadecimal string to relevant policy-asset (lower-case hex id)
const char* networkGetPolicyAsset(const char* network)
{
    JADE_ASSERT(isLiquidNetwork(network));

    // These are the policy assets for the liquid networks.
    // NOTE: 'rich' information should be present in the h/coded data in assets.c
    if (!strcmp(TAG_LIQUID, network)) {
        return "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
    } else if (!strcmp(TAG_TESTNETLIQUID, network)) {
        return "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    } else if (!strcmp(TAG_LOCALTESTLIQUID, network)) {
        return "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
    } else {
        return NULL;
    }
}
#endif // AMALGAMATED_BUILD
