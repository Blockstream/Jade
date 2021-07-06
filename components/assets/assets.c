#include <assert.h>
#include <string.h>

#include "assets.h"

#define ASSET_INFO(id, tickername, issuer, precis) \
    { .asset_id = id, .ticker = tickername, .issuer_domain = issuer, .precision = precis }

static const asset_info_t asset_info[] = {
    // These are not present in the asset registry data, or override what is there (as they are first).
    // These are the 'policy_assets' of liquid, testnet-liquid, and localtest-liquid
    ASSET_INFO("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d", "L-BTC", "peg-in", 8),  // liquid
    ASSET_INFO("5d8629bf58c7f98e90e171a81058ce543418f0dc16e8459367773552b067f3f3", "L-BTC", "peg-in (testnet)", 8),  // testnet-liquid
    ASSET_INFO("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", "L-BTC", "peg-in (localtest)", 8),  // localtest-liquid

    // Include the file generated from the asset registry json data file
    #include "asset_data.inc"
};

// Get h/coded asset info for small number of assets (by hex id)
const asset_info_t* assets_get_info(const char* asset_id)
{
    assert(asset_id);
    const size_t nassets = sizeof(asset_info) / sizeof(asset_info_t);
    for (const asset_info_t* passet = asset_info; passet < asset_info + nassets; ++passet)
    {
        assert(passet);
        if (!strcmp(asset_id, passet->asset_id))
        {
            return passet;
        }
    }
    return NULL;
}
