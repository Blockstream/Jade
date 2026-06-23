#ifndef DESCRIPTOR_H_
#define DESCRIPTOR_H_

#include "jade_assert.h"
#include "signer.h"
#include "utils/network.h"

struct wally_map;

// The length of a descriptor wallet name (see also storage key name size limit)
#define MAX_DESCRIPTOR_NAME_SIZE 16

// The maximum number of concurrent descriptor registrations supported
#define MAX_DESCRIPTOR_REGISTRATIONS 16

// The maximum length of the descriptor script
#define MAX_DESCRIPTOR_SCRIPT_LEN 512

// The size of the byte-string required to store a descriptor registration of the current 'version'
#define DESCRIPTOR_BYTES_LEN(descriptor)                                                                               \
    ((2 * sizeof(uint8_t)) + sizeof(descriptor->script_len) + descriptor->script_len + sizeof(uint8_t)                 \
        + (descriptor->num_values * 2 * sizeof(uint16_t))                                                              \
        + string_values_len(descriptor->values, descriptor->num_values) + HMAC_SHA256_LEN)

// The largest supported descriptor record
// NOTE: beware of a later 'version' reducing this size as we may end up with larger records persisted in storage
#define MAX_DESCRIPTOR_BYTES_LEN                                                                                       \
    (2 + 2 + MAX_DESCRIPTOR_SCRIPT_LEN + 1 + (MAX_ALLOWED_SIGNERS * 2 * 2) + (MAX_ALLOWED_SIGNERS * (160 + 16))        \
        + HMAC_SHA256_LEN)

typedef enum { DESCRIPTOR_TYPE_UNKNOWN, DESCRIPTOR_TYPE_MINISCRIPT_ONLY, DESCRIPTOR_TYPE_MIXED } descriptor_type_t;

// Strings for the descriptor mapped values
typedef struct {
    char value[160]; // should be sufficient for most keys/values
    char key[16];
    uint16_t value_len;
    uint16_t key_len;
} string_value_t;

// Descriptor data as persisted
typedef struct _descriptor_data {
    string_value_t values[MAX_ALLOWED_SIGNERS];
    char script[MAX_DESCRIPTOR_SCRIPT_LEN];
    uint16_t script_len;
    uint8_t num_values;
    descriptor_type_t type;
} descriptor_data_t;

// Get total length of string values
size_t string_values_len(const string_value_t* datavalues, size_t num_values);

bool descriptor_allow_liquid(void);

// Parse the descriptor and get signer information
// If `signers` is NULL then only the number of signers is returned in `written` (and `blinding_key` is ignored).
// If `blinding_key` is non-NULL, then the blinding key hex value is returned (if present in descriptor)
//    - caller must free the blinding key with wally_free_string().
WARN_UNUSED_RESULT bool descriptor_get_signers(const char* name, const descriptor_data_t* descriptor,
    const network_t network_id, descriptor_type_t* type, signer_t* signers, size_t signers_len, size_t* written,
    char** blinding_key, const char** errmsg);

// Generate an address using a descriptor/miniscript expression
// On success output must be freed with wally_free_string()
WARN_UNUSED_RESULT bool descriptor_to_address(const char* name, const descriptor_data_t* descriptor,
    const network_t network_id, uint32_t multi_index, uint32_t child_num, descriptor_type_t* type, char** output,
    const char** errmsg);

// Generate a script using a descriptor/miniscript expression
// On success output must be freed
// NOTE: For miniscript expressions, the script generated is untyped bitcoin script.
//       For descriptors, a scriptPubKey is generated.
WARN_UNUSED_RESULT bool descriptor_to_script(const char* name, const descriptor_data_t* descriptor,
    const network_t network_id, uint32_t multi_index, uint32_t child_num, descriptor_type_t* type, uint8_t** output,
    size_t* output_len, const char** errmsg);

// Iterate over a number of leaf child indexes testing the generated script for a match against the passed script
WARN_UNUSED_RESULT bool descriptor_search_for_script(const char* name, const descriptor_data_t* descriptor,
    const network_t network_id, uint32_t multi_index, uint32_t* child_num, size_t search_depth, const uint8_t* script,
    size_t script_len);

// Storage related functions
WARN_UNUSED_RESULT bool descriptor_to_bytes(descriptor_data_t* descriptor, uint8_t* output_bytes, size_t output_len);
WARN_UNUSED_RESULT bool descriptor_from_bytes(const uint8_t* bytes, size_t bytes_len, descriptor_data_t* descriptor);
WARN_UNUSED_RESULT bool descriptor_load_from_storage(
    const char* descriptor_name, descriptor_data_t* output, const char** errmsg);
void descriptor_get_valid_record_names(
    char names[][MAX_DESCRIPTOR_NAME_SIZE], const size_t num_names, size_t* num_written);

#endif /* DESCRIPTOR_H_ */
