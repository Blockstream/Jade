#ifndef JADE_ASSETS_ASSETS_H_
#define JADE_ASSETS_ASSETS_H_

#include <stdint.h>

typedef struct {
    // Asset-id as a hex string
    const char* asset_id;
    const char* ticker;
    const char* issuer_domain;
    uint8_t precision;
} asset_info_t;

const asset_info_t* assets_get_info(const char* asset_id);

#endif /* JADE_ASSETS_ASSETS_H_ */
