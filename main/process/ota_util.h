#ifndef JADE_OTA_UTIL_H_
#define JADE_OTA_UTIL_H_

#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include <deflate.h>
#include <esp_app_format.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <mbedtls/sha256.h>
#include <stdbool.h>
#include <stddef.h>

#define CUSTOM_HEADER_MIN_WRITE                                                                                        \
    (sizeof(esp_app_desc_t) + sizeof(esp_custom_app_desc_t) + sizeof(esp_image_header_t)                               \
        + sizeof(esp_image_segment_header_t))

// This structure is built into every fw, so we can check downloaded firmware
// is appropriate for the hardware unit we are trying to flash it onto.
// NOTE: For back compat only add to the end of the structure, and increase 'version'
// to indicate those new fields are present.
typedef struct {
    // Version 1 fields
    const uint8_t version;
    const char board_type[32];
    const char features[32];
    const char config[32];

    // Version 2 fields
    // add new fields here
} esp_custom_app_desc_t;

typedef enum { HASHTYPE_FILEDATA, HASHTYPE_FULLFWDATA } hash_type_t;

typedef enum {
    OTA_SUCCESS = 0,
    OTA_ERR_SETUP,
    OTA_ERR_INIT,
    OTA_ERR_BADPARTITION,
    OTA_ERR_DECOMPRESS,
    OTA_ERR_WRITE,
    OTA_ERR_FINISH,
    OTA_ERR_SETPARTITION,
    OTA_ERR_BADDATA,
    OTA_ERR_NODOWNGRADE,
    OTA_ERR_INVALIDFW,
    OTA_ERR_USERDECLINED,
    OTA_ERR_BADHASH,
    OTA_ERR_PATCH,
    OTA_ERR_PROTOCOL,
} ota_status_t;

typedef struct {
    // Context used to compute (compressed) firmware hash - ie. file as uploaded
    mbedtls_sha256_context sha_ctx;
    struct deflate_ctx dctx;
    progress_bar_t progress_bar;
    hash_type_t hash_type;
    char id[MAXLEN_ID + 1];
    uint8_t expected_hash[32];
    char* expected_hash_hexstr;
    const esp_partition_t* running_partition;
    const esp_partition_t* update_partition;
    esp_ota_handle_t ota_handle;
    ota_status_t ota_return_status;
    jade_msg_source_t expected_source;
    size_t compressedsize;
    size_t remaining_compressed;
    size_t uncompressedsize;
    size_t remaining_uncompressed;
    size_t firmwaresize;
    size_t fwwritten;
    bool extended_replies;
    bool validated_confirmed;
} jade_ota_ctx_t;

void handle_in_bin_data(void* ctx, uint8_t* data, size_t rawsize);

jade_ota_ctx_t* ota_init(jade_process_t* process, bool is_delta);
void ota_user_validate(jade_ota_ctx_t* joctx, const uint8_t* uncompressed);
void ota_finalize(jade_process_t* process, jade_ota_ctx_t* joctx, bool is_delta);

#endif /* JADE_OTA_UTIL_H_ */
