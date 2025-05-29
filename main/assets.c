#ifndef AMALGAMATED_BUILD
#include "assets.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "utils/malloc_ext.h"
#include "utils/network.h"
#include "utils/util.h"

#include <assets_snapshot.h>
#include <cbor.h>
#include <wally_address.h>
#include <wally_elements.h>
#include <wally_transaction.h>

#define ASSET_CONTRACT_BUFFER_LEN 768

// Compute the asset-id given the contract hash and the issuance prevout details
static void compute_asset_id(const uint8_t* contract_hash, const size_t contract_hash_len, const uint8_t* txhash,
    const size_t txhash_len, const size_t index, uint8_t* assetid, const size_t assetid_len)
{
    JADE_ASSERT(contract_hash);
    JADE_ASSERT(contract_hash_len == SHA256_LEN);
    JADE_ASSERT(txhash);
    JADE_ASSERT(txhash_len == WALLY_TXHASH_LEN);
    JADE_ASSERT(assetid);
    JADE_ASSERT(assetid_len == ASSET_TAG_LEN);

    uint8_t asset_entropy[SHA256_LEN];
    JADE_WALLY_VERIFY(wally_tx_elements_issuance_generate_entropy(
        txhash, txhash_len, index, contract_hash, contract_hash_len, asset_entropy, sizeof(asset_entropy)));

    uint8_t calcid[SHA256_LEN];
    JADE_WALLY_VERIFY(
        wally_tx_elements_issuance_calculate_asset(asset_entropy, sizeof(asset_entropy), calcid, sizeof(calcid)));

    // Reverse calculated id into the returned asset-id buffer
    for (size_t i = 0; i < sizeof(calcid); ++i) {
        assetid[i] = calcid[sizeof(calcid) - 1 - i];
    }
}

// Compute the contract hash - the sha256(contract_data_as_compact_json)
static bool get_asset_contract_hash(const CborValue* contract, uint8_t* contract_hash, const size_t contract_hash_len)
{
    JADE_ASSERT(contract);
    JADE_ASSERT(contract_hash);
    JADE_ASSERT(contract_hash_len == SHA256_LEN);

    char contract_json[ASSET_CONTRACT_BUFFER_LEN];
    FILE* const fstr = fmemopen((uint8_t*)contract_json, sizeof(contract_json), "w");
    if (cbor_value_to_json(fstr, contract, CborConvertDefaultFlags) != CborNoError) {
        JADE_LOGE("Failed to convert asset contract data to json");
        fclose(fstr);
        return false;
    }
    fclose(fstr);

    const size_t contract_json_len = strnlen(contract_json, sizeof(contract_json));
    JADE_ASSERT(contract_json_len > 0 && contract_json_len < sizeof(contract_json));

    return wally_sha256((uint8_t*)contract_json, contract_json_len, contract_hash, contract_hash_len) == WALLY_OK;
}

// Asset data is optional - but if present it must be correct/valid
bool assets_get_allocate(const char* field, const CborValue* value, asset_info_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_INIT_OUT_PPTR(data);
    JADE_INIT_OUT_SIZE(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        // No asset data present is not an error
        return true;
    }

    size_t num_array_items = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_array_items);
    if (cberr != CborNoError) {
        return false;
    }

    if (num_array_items == 0) {
        // No asset data present is not an error
        return true;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return false;
    }

    asset_info_t* const assets = JADE_CALLOC(num_array_items, sizeof(asset_info_t));

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        asset_info_t* const asset = assets + i;

        if (cbor_value_is_map(&arrayItem)) {
            // We compute the asset-id from the contract and issuance details
            CborValue contract;
            if (!rpc_get_map("contract", &arrayItem, &contract)) {
                free(assets);
                return false;
            }

            uint8_t contract_hash[SHA256_LEN];
            if (!get_asset_contract_hash(&contract, contract_hash, sizeof(contract_hash))) {
                JADE_LOGE("Failed to compute asset contract hash, asset %d", i);
                free(assets);
                return false;
            }

            CborValue issuanceprevout;
            if (!rpc_get_map("issuance_prevout", &arrayItem, &issuanceprevout)) {
                free(assets);
                return false;
            }

            uint8_t txhash[WALLY_TXHASH_LEN];
            const char* txhashhex = NULL;
            size_t txhashhex_len = 0;
            size_t written = 0;
            rpc_get_string_ptr("txid", &issuanceprevout, &txhashhex, &txhashhex_len);
            if (wally_hex_n_to_bytes(txhashhex, txhashhex_len, txhash, sizeof(txhash), &written) != WALLY_OK
                || written != sizeof(txhash)) {
                JADE_LOGE("Failed to get txhash for issuance prevout");
                free(assets);
                return false;
            }
            reverse_in_place(txhash, sizeof(txhash));

            size_t index;
            if (!rpc_get_sizet("vout", &issuanceprevout, &index)) {
                free(assets);
                return false;
            }

            // Compute the asset-id based on the contract and issuance details
            uint8_t computed_id[ASSET_TAG_LEN];
            compute_asset_id(
                contract_hash, sizeof(contract_hash), txhash, sizeof(txhash), index, computed_id, sizeof(computed_id));

            // Error if computed asset-id mismatches with what was passed
            const char* asset_id_hex = NULL;
            size_t asset_id_hex_len = 0;
            rpc_get_string_ptr("asset_id", &arrayItem, &asset_id_hex, &asset_id_hex_len);

            uint8_t asset_id[ASSET_TAG_LEN];
            if (wally_hex_n_to_bytes(asset_id_hex, asset_id_hex_len, asset_id, sizeof(asset_id), &written) != WALLY_OK
                || written != sizeof(asset_id) || memcmp(computed_id, asset_id, sizeof(asset_id))) {
                JADE_LOGE("Asset id failed verification: %.*s", asset_id_hex_len, asset_id_hex);
                free(assets);
                return false;
            }

            // Populate the asset_info data elements from the contract data
            asset->asset_id = asset_id_hex;
            asset->asset_id_len = asset_id_hex_len;

            rpc_get_string_ptr("ticker", &contract, &asset->ticker, &asset->ticker_len);

            CborValue entity;
            if (rpc_get_map("entity", &contract, &entity)) {
                rpc_get_string_ptr("domain", &entity, &asset->issuer_domain, &asset->issuer_domain_len);
            }

            size_t precision = 0;
            rpc_get_sizet("precision", &contract, &precision);
            asset->precision = precision;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(assets);
        return false;
    }

    *written = num_array_items;
    *data = assets;
    return true;
}

// Lookup asset-info for the passed asset-id.
// 1. Looks in any explicitly passed asset-info
// 2. Looks in any h/coded asset snapshot data (eg. policy assets)
bool assets_get_info(const uint32_t network_id, const asset_info_t* assets, const size_t num_assets,
    const char* asset_id, asset_info_t* asset_info_out)
{
    JADE_ASSERT(network_is_liquid(network_id));
    JADE_ASSERT(assets || !num_assets);
    JADE_ASSERT(asset_id);

    // 1. Search provided asset data
    if (assets) {
        for (const asset_info_t* passet = assets; passet < assets + num_assets; ++passet) {
            if (!strncmp(asset_id, passet->asset_id, passet->asset_id_len) && asset_id[passet->asset_id_len] == '\0') {
                // Shallow copy of pointers and sizes is good
                *asset_info_out = *passet;
                return true;
            }
        }
    }

    // 3. Search the h/coded assets snapshot
    // FIXME: WALLY_NETWORK_LIQUID_REGTEST appears to use mainnet assets?
    const bool use_testnet_registry = network_id == WALLY_NETWORK_LIQUID_TESTNET /* ||
        network_id == WALLY_NETWORK_LIQUID_REGTEST */
        ;
    const snapshot_asset_info_t* snapshot_asset = assets_snapshot_get_info(asset_id, use_testnet_registry);
    if (snapshot_asset) {
        // Copy pointers and deduce sizes (as snapshot fields are nul-terminated strings)
        asset_info_out->asset_id = snapshot_asset->asset_id;
        asset_info_out->asset_id_len = strlen(snapshot_asset->asset_id);

        asset_info_out->issuer_domain = snapshot_asset->issuer_domain;
        asset_info_out->issuer_domain_len = strlen(snapshot_asset->issuer_domain);

        asset_info_out->ticker = snapshot_asset->ticker;
        asset_info_out->ticker_len = strlen(snapshot_asset->ticker);

        asset_info_out->precision = snapshot_asset->precision;
        return true;
    }

    // Not found in passed info nor in h/coded snapshot info
    return false;
}
#endif // AMALGAMATED_BUILD
