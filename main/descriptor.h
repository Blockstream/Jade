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

#endif /* DESCRIPTOR_H_ */
