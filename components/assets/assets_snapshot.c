#include <assert.h>
#include <string.h>

#include "assets_snapshot.h"

#define ASSET_INFO(id, tickername, issuer, precis) \
    { .asset_id = id, .ticker = tickername, .issuer_domain = issuer, .precision = precis }

// Mainnet asset registry (also used for regtest?)
static const snapshot_asset_info_t assets_snapshot[] = {
    // These are not present in the asset registry data, or override what is there (as they are first).
    // These are the 'policy_assets' of liquid and localtest-liquid
    ASSET_INFO("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d", "L-BTC", "peg-in", 8),  // liquid
    ASSET_INFO("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", "L-BTC", "peg-in (localtest)", 8),  // localtest-liquid

    // Include the file generated from the asset registry json data file
    #include "asset_data.inc"
};

// Testnet asset registry
static const snapshot_asset_info_t assets_snapshot_testnet[] = {
    // These are not present in the asset registry data, or override what is there (as they are first).
    // This is the 'policy_asset' of testnet-liquid
    ASSET_INFO("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49", "L-TEST", "peg-in (testnet)", 8),  // testnet-liquid

    // Include the file generated from the testnet asset registry json data file
    #include "asset_data_testnet.inc"
};

// Get h/coded snapshot asset info (by hex id)
const snapshot_asset_info_t* assets_snapshot_get_info(const char* asset_id, const bool use_testnet_registry)
{
    assert(asset_id);

    const snapshot_asset_info_t* assets = use_testnet_registry ? assets_snapshot_testnet : assets_snapshot;
    const size_t sizeof_asset_array = use_testnet_registry ? sizeof(assets_snapshot_testnet) : sizeof(assets_snapshot);

    const size_t nassets = sizeof_asset_array / sizeof(snapshot_asset_info_t);
    for (const snapshot_asset_info_t* passet = assets; passet < assets + nassets; ++passet)
    {
        assert(passet);
        if (!strcmp(asset_id, passet->asset_id)) {
            return passet;
        }
    }
    return NULL;
}
