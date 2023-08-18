#ifndef DESCRIPTOR_H_
#define DESCRIPTOR_H_

#include "signer.h"

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

// Parse the descriptor and get signer information
bool descriptor_get_signers(const char* name, const descriptor_data_t* descriptor, const char* network,
    descriptor_type_t* type, signer_t* signers, size_t signers_len, size_t* written, const char** errmsg);

// Generate an address using a descriptor/miniscript expression
// On success output must be freed with wally_free_string()
bool descriptor_to_address(const char* name, const descriptor_data_t* descriptor, const char* network,
    uint32_t multi_index, uint32_t child_num, descriptor_type_t* type, char** output, const char** errmsg);

// Generate a script using a descriptor/miniscript expression
// On success output must be freed
// NOTE: For miniscript expressions, the script generated is untyped bitcoin script.
//       For descriptors, a scriptPubKey is generated.
bool descriptor_to_script(const char* name, const descriptor_data_t* descriptor, const char* network,
    uint32_t multi_index, uint32_t child_num, descriptor_type_t* type, uint8_t** output, size_t* output_len,
    const char** errmsg);

// Storage related functions
bool descriptor_to_bytes(descriptor_data_t* descriptor, uint8_t* output_bytes, size_t output_len);
bool descriptor_from_bytes(const uint8_t* bytes, size_t bytes_len, descriptor_data_t* descriptor);
bool descriptor_load_from_storage(const char* descriptor_name, descriptor_data_t* output, const char** errmsg);

#endif /* DESCRIPTOR_H_ */
