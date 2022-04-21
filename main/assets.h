#ifndef JADE_ASSETS_H_
#define JADE_ASSETS_H_

#include "utils/cbor_rpc.h"

// NOTE: strings here may not be nul-terminated as may directly reference message fields
typedef struct {
    const char* asset_id;
    const char* ticker;
    const char* issuer_domain;
    size_t asset_id_len;
    size_t ticker_len;
    size_t issuer_domain_len;
    uint8_t precision;
} asset_info_t;

bool assets_get_allocate(const char* field, const CborValue* value, asset_info_t** data, size_t* written);

bool assets_get_info(const char* network, const asset_info_t* assets, size_t num_assets, const char* asset_id,
    asset_info_t* asset_info_out);

#endif /* JADE_ASSETS_H_ */
