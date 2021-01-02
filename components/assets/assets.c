#include <assert.h>
#include <string.h>

#include "assets.h"

#define ASSET_INFO(id, tickername, issuer, precis) \
    { .asset_id = id, .ticker = tickername, .issuer_domain = issuer, .precision = precis }

static const asset_info_t asset_info[] = {
    // These are not present in the asset registry data, or override what is there (as they are first).
    ASSET_INFO("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d", "L-BTC", "peg-in", 8),

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
