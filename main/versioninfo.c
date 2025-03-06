#ifndef AMALGAMATED_BUILD
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "power.h"
#include "process.h"
#include "process/ota_defines.h"
#include "storage.h"
#include "utils/cbor_rpc.h"
#include "utils/network.h"
#include "utils/util.h"

#include <esp_app_desc.h>
#include <esp_chip_info.h>
#include <esp_idf_version.h>
#include <esp_mac.h>
#include <esp_ota_ops.h>

#include <ctype.h>

// The chip-info, mac-id, and running firmware-info, loaded at startup in main.c
extern esp_app_desc_t running_app_info;
extern esp_chip_info_t chip_info;
extern uint8_t macid[6];

void build_version_info_reply(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(container);

    const jade_msg_source_t* const source = (const jade_msg_source_t*)ctx;

#ifdef CONFIG_DEBUG_MODE
    const uint8_t num_version_fields = 20;
#else
    const uint8_t num_version_fields = 12;
#endif

    CborEncoder map_encoder;
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, num_version_fields);
    JADE_ASSERT(cberr == CborNoError);

    add_string_to_map(&map_encoder, "JADE_VERSION", running_app_info.version);
    add_uint_to_map(&map_encoder, "JADE_OTA_MAX_CHUNK", JADE_OTA_BUF_SIZE);

    // Config - eg. ble/radio enabled in build, or not
    // defined in ota.h
    add_string_to_map(&map_encoder, "JADE_CONFIG", JADE_OTA_CONFIG);

    // Board type - Production Jade, M5Stack, esp32 dev board, etc.
    // defined in ota.h
    add_string_to_map(&map_encoder, "BOARD_TYPE", JADE_OTA_BOARD_TYPE);

    // hardware 'features' eg. 'secure boot' or 'dev' etc.
    // defined in ota.h
    add_string_to_map(&map_encoder, "JADE_FEATURES", JADE_OTA_FEATURES);

    const char* idfversion = esp_get_idf_version();
    add_string_to_map(&map_encoder, "IDF_VERSION", idfversion);

    char* hexstr = NULL;
    JADE_WALLY_VERIFY(wally_hex_from_bytes((uint8_t*)&chip_info.features, 4, &hexstr));
    add_string_to_map(&map_encoder, "CHIP_FEATURES", hexstr);
    JADE_WALLY_VERIFY(wally_free_string(hexstr));

    JADE_WALLY_VERIFY(wally_hex_from_bytes(macid, 6, &hexstr));
    map_string(hexstr, toupper);
    add_string_to_map(&map_encoder, "EFUSEMAC", hexstr);
    JADE_WALLY_VERIFY(wally_free_string(hexstr));

    // Battery level
    add_uint_to_map(&map_encoder, "BATTERY_STATUS", power_get_battery_status());

    // We have five cases:
    // 1. Ready - has keys already associated with the passed message source
    //    - READY
    // 2. Temporary keys - has temporary keys in memory, but not yet connected to app
    //    - TEMP
    // 3. Unsaved keys - has proper keys in memory, but not yet saved with a PIN
    //    - UNSAVED
    // 4. Locked - has persisted/encrypted keys, but no keys in memory for the passed message source
    //    - LOCKED
    // 5. Uninitialised - has no persisted/encrypted keys and no keys in memory
    //    - UNINIT

    const bool has_pin = keychain_has_pin();
    const bool has_keys = keychain_get() != NULL;
    if (has_keys) {
        if (keychain_get_userdata() == *source) {
            add_string_to_map(&map_encoder, "JADE_STATE", "READY");
        } else if (keychain_get_userdata() != SOURCE_NONE) {
            // Other connection interface in use - so this interface is 'locked'
            add_string_to_map(&map_encoder, "JADE_STATE", "LOCKED");
        } else if (keychain_has_temporary()) {
            add_string_to_map(&map_encoder, "JADE_STATE", "TEMP");
        } else {
            add_string_to_map(&map_encoder, "JADE_STATE", "UNSAVED");
        }
    } else {
        add_string_to_map(&map_encoder, "JADE_STATE", has_pin ? "LOCKED" : "UNINIT");
    }

    const network_type_t restriction = keychain_get_network_type_restriction();
    const char* networks = restriction == NETWORK_TYPE_MAIN ? "MAIN"
        : restriction == NETWORK_TYPE_TEST                  ? "TEST"
                                                            : "ALL";
    add_string_to_map(&map_encoder, "JADE_NETWORKS", networks);

    // Deprecated (as of 0.1.25) - to be removed later
    add_boolean_to_map(&map_encoder, "JADE_HAS_PIN", has_pin);

// Memory stats only needed in DEBUG
#ifdef CONFIG_DEBUG_MODE
    size_t entries_used, entries_free;
    const bool ok = storage_get_stats(&entries_used, &entries_free);
    add_uint_to_map(&map_encoder, "JADE_NVS_ENTRIES_USED", ok ? entries_used : 0);
    add_uint_to_map(&map_encoder, "JADE_NVS_ENTRIES_FREE", ok ? entries_free : 0);

    add_uint_to_map(&map_encoder, "JADE_FREE_HEAP", xPortGetFreeHeapSize());
    add_uint_to_map(&map_encoder, "JADE_FREE_DRAM", heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));
    add_uint_to_map(
        &map_encoder, "JADE_LARGEST_DRAM", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));
    add_uint_to_map(&map_encoder, "JADE_FREE_SPIRAM", heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM));
    add_uint_to_map(
        &map_encoder, "JADE_LARGEST_SPIRAM", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_SPIRAM));
#ifdef CONFIG_APPTRACE_GCOV_ENABLE
    add_boolean_to_map(&map_encoder, "GCOV", true);
#else
    add_boolean_to_map(&map_encoder, "GCOV", false);
#endif
#endif // CONFIG_DEBUG_MODE

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}
#endif // AMALGAMATED_BUILD
