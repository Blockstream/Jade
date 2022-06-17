#ifndef ASSETS_ASSETS_SNAPSHOT_H_
#define ASSETS_ASSETS_SNAPSHOT_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// NOTE: all strings in the snapshot data are nul-terminated
typedef struct {
    // Asset-id as a hex string
    const char* asset_id;
    const char* ticker;
    const char* issuer_domain;
    uint8_t precision;
} snapshot_asset_info_t;

const snapshot_asset_info_t* assets_snapshot_get_info(const char* asset_id, bool use_testnet_registry);

#endif /* ASSETS_ASSET_SNAPSHOT_H_ */
