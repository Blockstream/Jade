#ifndef PROCESS_UTILS_H_
#define PROCESS_UTILS_H_

#include "../keychain.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#define COMMITMENTS_NONE 0x0
#define COMMITMENTS_ABF 0x1
#define COMMITMENTS_VBF 0x2
#define COMMITMENTS_BLINDING_KEY 0x4
#define COMMITMENTS_ASSET_BLIND_PROOF 0x8
#define COMMITMENTS_VALUE_BLIND_PROOF 0x10
#define COMMITMENTS_INCLUDES_COMMITMENTS 0x20

typedef struct {
    uint8_t asset_blind_proof[ASSET_EXPLICIT_SURJECTIONPROOF_LEN];
    uint8_t value_blind_proof[ASSET_EXPLICIT_RANGEPROOF_MAX_LEN];
    uint8_t asset_generator[ASSET_GENERATOR_LEN];
    uint8_t value_commitment[ASSET_COMMITMENT_LEN];
    uint8_t asset_id[ASSET_TAG_LEN];
    uint8_t abf[BLINDING_FACTOR_LEN];
    uint8_t vbf[BLINDING_FACTOR_LEN];
    uint8_t blinding_key[EC_PUBLIC_KEY_LEN];
    uint64_t value;
    size_t value_blind_proof_len;
    uint8_t content;
} commitment_t;

#define MAX_REQUEST_URLS 2

#define CLIENT_REQUEST_TYPE_HTTP "http_request"

typedef struct {
    const char* urls[MAX_REQUEST_URLS];
    const char* request_type;
    const char* certificate;
    const char* method;
    const char* accept;
    union {
        const char* strdata;
        const uint8_t* rawdata;
    };
    const char* on_reply;
    size_t rawdata_len; // zero implies may be char data
    uint8_t num_urls;
} client_data_request_t;

#define HAS_NO_CURRENT_MESSAGE(process)                                                                                \
    (process && !process->ctx.cbor && !process->ctx.cbor_len && process->ctx.source == SOURCE_NONE)

#define HAS_CURRENT_MESSAGE(process)                                                                                   \
    (process && process->ctx.cbor && process->ctx.cbor_len && process->ctx.source != SOURCE_NONE)

#define IS_CURRENT_MESSAGE(process, method)                                                                            \
    (process && process->ctx.cbor && process->ctx.cbor_len && process->ctx.source != SOURCE_NONE                       \
        && rpc_request_valid(&process->ctx.value) && rpc_is_method(&process->ctx.value, method))

#define ASSERT_NO_CURRENT_MESSAGE(process) JADE_ASSERT(HAS_NO_CURRENT_MESSAGE(process))
#define ASSERT_HAS_CURRENT_MESSAGE(process) JADE_ASSERT(HAS_CURRENT_MESSAGE(process))
#define ASSERT_CURRENT_MESSAGE(process, method) JADE_ASSERT(IS_CURRENT_MESSAGE(process, method))

// Get the parameters for the current process message.
// Declares 'params' to hold them, assumes a 'cleanup' label exists.
#define GET_MSG_PARAMS(process)                                                                                        \
    CborValue params;                                                                                                  \
    const CborError _cberr = cbor_value_map_find_value(&process->ctx.value, CBOR_RPC_TAG_PARAMS, &params);             \
    if (_cberr != CborNoError || !cbor_value_is_valid(&params) || cbor_value_get_type(&params) == CborInvalidType      \
        || !cbor_value_is_map(&params)) {                                                                              \
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Expecting parameters map");                     \
        goto cleanup;                                                                                                  \
    }

bool jade_process_check_network(jade_process_t* process, CborValue* params, network_t* network_id);

// Ensure the rpc "network" parameter is valid and consistent with prior use.
// Declares 'network_id' variable and initializes it.
// Assumes GET_MSG_PARAMS() was used previously in the same scope.
#define CHECK_NETWORK_CONSISTENT(process)                                                                              \
    network_t network_id;                                                                                              \
    if (!jade_process_check_network(process, &params, &network_id)) {                                                  \
        goto cleanup;                                                                                                  \
    }

// Do we have have a keychain, and does its userdata indicate the same 'source'
// as the current message ?
// This is to check that we only handle messages from the same source (serial or ble)
// as initially unlocked the key material.
#define KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)                                                                   \
    (keychain_get() && keychain_get_userdata() == (uint8_t)process->ctx.source)

#define ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process) JADE_ASSERT(KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process))

// For tracking input types
typedef enum {
    SCRIPT_FLAVOUR_NONE,
    SCRIPT_FLAVOUR_SINGLESIG,
    SCRIPT_FLAVOUR_MULTISIG,
    SCRIPT_FLAVOUR_OTHER,
    SCRIPT_FLAVOUR_MIXED
} script_flavour_t;

#define WARN_MSG_HIGH_FEES "Fee amount higher than spend amount!"
#define WARN_MSG_MIXED_INPUTS "Your transaction inputs are of varying types."

// Sanity check extended-data payload fields
bool check_extended_data_fields(CborValue* params, const char* expected_origid, const char* expected_orig,
    size_t expected_seqnum, size_t expected_seqlen);

// Common parameter extraction/handling
int params_set_epoch_time(CborValue* params, const char** errmsg);

bool params_identity_curve_index(CborValue* params, const char** identity, size_t* identity_len, const char** curve,
    size_t* curve_len, size_t* index, const char** errmsg);

bool params_hashprevouts_outputindex(CborValue* params, const uint8_t** hash_prevouts, size_t* hash_prevouts_len,
    size_t* output_index, const char** errmsg);

typedef struct _descriptor_data descriptor_data_t;
bool params_load_descriptor(CborValue* params, char* descriptor_name, const size_t descriptor_name_len,
    descriptor_data_t* descriptor, const char** errmsg);

typedef struct _multisig_data multisig_data_t;
bool params_load_multisig(CborValue* params, char* multisig_name, size_t multisig_name_len,
    multisig_data_t* multisig_data, const char** errmsg);
bool params_multisig_pubkeys(bool is_change, CborValue* params, multisig_data_t* multisig_data, uint8_t* pubkeys,
    size_t pubkeys_len, size_t* pubkeys_written, char* warningmsg, size_t warningmsg_len, const char** errmsg);
bool params_get_master_blindingkey(
    CborValue* params, uint8_t* master_blinding_key, size_t master_blinding_key_len, const char** errmsg);

bool params_tx_input_signing_data(const bool use_ae_signatures, CborValue* params, input_data_t* sig_data,
    const uint8_t** ae_host_commitment, size_t* ae_host_commitment_len, const uint8_t** script, size_t* script_len,
    script_flavour_t* aggregate_script_flavour, const char** errmsg);

bool params_get_bip85_rsa_key(CborValue* params, size_t* key_bits, size_t* index, const char** errmsg);

// Track the types of the input prevout scripts
script_flavour_t get_script_flavour(const uint8_t* script, const size_t script_len, bool* is_p2tr);
void update_aggregate_scripts_flavour(script_flavour_t new_script_flavour, script_flavour_t* aggregate_scripts_flavour);

// A message reply which is actually a request for more data from the client
// 'ctx' should be a 'client_data_request_t' struct as above
void client_data_request_reply(const void* ctx, CborEncoder* container);

#endif /* PROCESS_UTILS_H_ */
