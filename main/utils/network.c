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
bool network_is_liquid(const network_t network_id)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    return network_id == NETWORK_LIQUID || network_id == NETWORK_LIQUID_TESTNET || network_id == NETWORK_LIQUID_REGTEST;
}

// return the allowed csv_blocks values for a network
static size_t network_to_csv_blocks(const network_t network_id, const size_t** allowed)
{
    JADE_INIT_OUT_PPTR(allowed);

    switch (network_id) {
    case NETWORK_BITCOIN:
        *allowed = ALLOWED_CSV_MAINNET;
        return sizeof(ALLOWED_CSV_MAINNET) / sizeof(ALLOWED_CSV_MAINNET[0]);
    case NETWORK_LIQUID:
        *allowed = ALLOWED_CSV_LIQUID;
        return sizeof(ALLOWED_CSV_LIQUID) / sizeof(ALLOWED_CSV_LIQUID[0]);
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        *allowed = ALLOWED_CSV_TESTNET;
        return sizeof(ALLOWED_CSV_TESTNET) / sizeof(ALLOWED_CSV_TESTNET[0]);
    case NETWORK_LIQUID_TESTNET:
    case NETWORK_LIQUID_REGTEST:
        *allowed = ALLOWED_CSV_TESTNET_LIQUID;
        return sizeof(ALLOWED_CSV_TESTNET_LIQUID) / sizeof(ALLOWED_CSV_TESTNET_LIQUID[0]);
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown network
}

// True if csv_blocks is one of the networks hard-coded csv_blocks values
bool network_is_known_csv_blocks(const network_t network_id, const uint32_t csv_blocks)
{
    const size_t* allowed = NULL;
    const size_t num_allowed = network_to_csv_blocks(network_id, &allowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(allowed);

    for (size_t i = 0; i < num_allowed; ++i) {
        if (csv_blocks == allowed[i]) {
            return true;
        }
    }

    return false;
}

// True if csv_blocks is not below the networks smallest csv_blocks value
bool network_is_allowable_csv_blocks(const network_t network_id, const uint32_t csv_blocks)
{
    const size_t* allowed = NULL;
    const size_t num_allowed = network_to_csv_blocks(network_id, &allowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(allowed);

    return csv_blocks >= allowed[0];
}

network_t network_from_name(const char* name)
{
    // Ensure our enum values match the libwally constants
    JADE_STATIC_ASSERT(NETWORK_NONE == WALLY_NETWORK_NONE);
    JADE_STATIC_ASSERT(NETWORK_BITCOIN == WALLY_NETWORK_BITCOIN_MAINNET);
    JADE_STATIC_ASSERT(NETWORK_BITCOIN_REGTEST == WALLY_NETWORK_BITCOIN_REGTEST);
    JADE_STATIC_ASSERT(NETWORK_BITCOIN_TESTNET == WALLY_NETWORK_BITCOIN_TESTNET);
    JADE_STATIC_ASSERT(NETWORK_LIQUID == WALLY_NETWORK_LIQUID);
    JADE_STATIC_ASSERT(NETWORK_LIQUID_REGTEST == WALLY_NETWORK_LIQUID_REGTEST);
    JADE_STATIC_ASSERT(NETWORK_LIQUID_TESTNET == WALLY_NETWORK_LIQUID_TESTNET);

    if (name) {
        if (!strcmp(TAG_MAINNET, name)) {
            return NETWORK_BITCOIN;
        } else if (!strcmp(TAG_LIQUID, name)) {
            return NETWORK_LIQUID;
        } else if (!strcmp(TAG_TESTNET, name)) {
            return NETWORK_BITCOIN_TESTNET;
        } else if (!strcmp(TAG_TESTNETLIQUID, name)) {
            return NETWORK_LIQUID_TESTNET;
        } else if (!strcmp(TAG_LOCALTEST, name)) {
            return NETWORK_BITCOIN_REGTEST;
        } else if (!strcmp(TAG_LOCALTESTLIQUID, name)) {
            return NETWORK_LIQUID_REGTEST;
        }
    }
    return NETWORK_NONE;
}

const char* network_to_name(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return TAG_MAINNET;
    case NETWORK_LIQUID:
        return TAG_LIQUID;
    case NETWORK_BITCOIN_TESTNET:
        return TAG_TESTNET;
    case NETWORK_LIQUID_TESTNET:
        return TAG_TESTNETLIQUID;
    case NETWORK_BITCOIN_REGTEST:
        return TAG_LOCALTEST;
    case NETWORK_LIQUID_REGTEST:
        return TAG_LOCALTESTLIQUID;
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false);
    return NULL; // Unreachable
}

// network id to type (main or test)
network_type_t network_to_type(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
    case NETWORK_LIQUID:
        return NETWORK_TYPE_MAIN;
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_LIQUID_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
    case NETWORK_LIQUID_REGTEST:
        return NETWORK_TYPE_TEST;
    case NETWORK_NONE:
        break;
    }
    return NETWORK_TYPE_NONE;
}

// network id to BIP32 key version.
// Mainnets map to VER_MAIN_PRIVATE, testnets to VER_TEST_PRIVATE
uint32_t network_to_bip32_version(const network_t network_id)
{
    const network_type_t network_type = network_to_type(network_id);
    JADE_ASSERT(network_type != NETWORK_TYPE_NONE);
    return network_type == NETWORK_TYPE_MAIN ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
}

// network id to relevant P2PKH address prefix
uint8_t network_to_p2pkh_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return WALLY_ADDRESS_VERSION_P2PKH_MAINNET;
    case NETWORK_LIQUID:
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID;
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        return WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
    case NETWORK_LIQUID_TESTNET:
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET;
    case NETWORK_LIQUID_REGTEST:
        return WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST;
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant P2SH address prefix
uint8_t network_to_p2sh_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return WALLY_ADDRESS_VERSION_P2SH_MAINNET;
    case NETWORK_LIQUID:
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID;
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        return WALLY_ADDRESS_VERSION_P2SH_TESTNET;
    case NETWORK_LIQUID_TESTNET:
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET;
    case NETWORK_LIQUID_REGTEST:
        return WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST;
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant bech32 hrp
const char* network_to_bech32_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return "bc";
    case NETWORK_LIQUID:
        return "ex";
    case NETWORK_BITCOIN_TESTNET:
        return "tb";
    case NETWORK_BITCOIN_REGTEST:
        return "bcrt";
    case NETWORK_LIQUID_TESTNET:
        return "tex";
    case NETWORK_LIQUID_REGTEST:
        return "ert";
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return NULL; // Unreachable
}

// network id to relevant confidential address prefix
uint8_t network_to_confidential_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_LIQUID:
        return WALLY_CA_PREFIX_LIQUID;
    case NETWORK_LIQUID_TESTNET:
        return WALLY_CA_PREFIX_LIQUID_TESTNET;
    case NETWORK_LIQUID_REGTEST:
        return WALLY_CA_PREFIX_LIQUID_REGTEST;
    default:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant confidential blech32 hrp
const char* network_to_blech32_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_LIQUID:
        return "lq";
    case NETWORK_LIQUID_TESTNET:
        return "tlq";
    case NETWORK_LIQUID_REGTEST:
        return "el";
    default:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant policy-asset (lower-case hex id)
const char* network_to_policy_asset_hex(const network_t network_id)
{
    // These are the policy assets for the liquid networks.
    // NOTE: 'rich' information should be present in the h/coded data in assets.c
    switch (network_id) {
    case NETWORK_LIQUID:
        return "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
    case NETWORK_LIQUID_TESTNET:
        return "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    case NETWORK_LIQUID_REGTEST:
        return "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
    default:
        break;
    }
    JADE_ASSERT(false); // Not a liquid network
    return NULL; // Unreachable
}
#endif // AMALGAMATED_BUILD
