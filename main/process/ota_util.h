#ifndef JADE_OTA_UTIL_H_
#define JADE_OTA_UTIL_H_

#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include <stdbool.h>
#include <stddef.h>
#define VERSION_STRING_MAX_LENGTH 32
#define UNCOMPRESSED_BUF_SIZE 32768

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

struct bin_msg {
    char id[MAXLEN_ID + 1];
    uint8_t* inbound_buf;
    size_t len;
    jade_msg_source_t expected_source;
    bool loaded;
    bool error;
};

enum ota_status {
    SUCCESS,
    ERROR_OTA_SETUP,
    ERROR_OTA_INIT,
    ERROR_BADPARTITION,
    ERROR_DECOMPRESS,
    ERROR_WRITE,
    ERROR_FINISH,
    ERROR_SETPARTITION,
    ERROR_TIMEOUT,
    ERROR_BADDATA,
    ERROR_NODOWNGRADE,
    ERROR_INVALIDFW,
    ERROR_USER_DECLINED,
    ERROR_BAD_HASH,
};

// status messages
static const char MESSAGES[][20] = {
    "OK",
    "ERROR_OTA_SETUP",
    "ERROR_OTA_INIT",
    "ERROR_BADPARTITION",
    "ERROR_DECOMPRESS",
    "ERROR_WRITE",
    "ERROR_FINISH",
    "ERROR_SETPARTITION",
    "ERROR_TIMEOUT",
    "ERROR_BADDATA",
    "ERROR_NODOWNGRADE",
    "ERROR_INVALIDFW",
    "ERROR_USER_DECLINED",
    "ERROR_BAD_HASH",
};

bool validate_custom_app_desc(const size_t offset, const unsigned char* uncompressed);
void send_ok(const char* id, const jade_msg_source_t source);
void reset_ctx(struct bin_msg* bctx, uint8_t* const inbound_buf, const jade_msg_source_t expected_source);
void handle_in_bin_data(void* ctx, unsigned char* data, size_t rawsize);

// UI screens to confirm ota
void make_ota_versions_activity(gui_activity_t** activity_ptr, const char* current_version, const char* new_version,
    const char* expected_hash_hexstr);

#endif /* JADE_OTA_UTIL_H_ */
