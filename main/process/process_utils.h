#ifndef PROCESS_UTILS_H_
#define PROCESS_UTILS_H_

#define ASSERT_NO_CURRENT_MESSAGE(process)                                                                             \
    JADE_ASSERT(process && !process->ctx.cbor && !process->ctx.cbor_len && process->ctx.source == SOURCE_NONE)

#define ASSERT_HAS_CURRENT_MESSAGE(process)                                                                            \
    JADE_ASSERT(process && process->ctx.cbor && process->ctx.cbor_len && process->ctx.source != SOURCE_NONE)

#define ASSERT_CURRENT_MESSAGE(process, method)                                                                        \
    JADE_ASSERT(process && process->ctx.cbor && process->ctx.cbor_len && process->ctx.source != SOURCE_NONE            \
        && rpc_request_valid(&process->ctx.value) && rpc_is_method(&process->ctx.value, method))

// Assumes 'cleanup' label exists
#define GET_MSG_PARAMS(process)                                                                                        \
    CborValue params;                                                                                                  \
    const CborError _cberr = cbor_value_map_find_value(&process->ctx.value, CBOR_RPC_TAG_PARAMS, &params);             \
    if (_cberr != CborNoError || !cbor_value_is_valid(&params) || cbor_value_get_type(&params) == CborInvalidType      \
        || !cbor_value_is_map(&params)) {                                                                              \
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Expecting parameters map", NULL);               \
        goto cleanup;                                                                                                  \
    }

// Ensure network is valid and consistent with prior usage
// Assumes 'cleanup' label exists
#define CHECK_NETWORK_CONSISTENT(process, network, network_len)                                                        \
    if (network_len == 0 || !isValidNetwork(network)) {                                                                \
        jade_process_reject_message(                                                                                   \
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid network from parameters", NULL);                \
        goto cleanup;                                                                                                  \
    } else if (!keychain_is_network_type_consistent(network)) {                                                        \
        jade_process_reject_message(                                                                                   \
            process, CBOR_RPC_NETWORK_MISMATCH, "Network type inconsistent with prior usage", NULL);                   \
        goto cleanup;                                                                                                  \
    }

// Do we have have a keychain, and does its userdata indicate the same 'source'
// as the current message ?
// This is to check that we only handle messages from the same source (serial or ble)
// as initially unlocked the key material.
#define KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process)                                                                   \
    (keychain_get() && keychain_get_userdata() == (uint8_t)process->ctx.source)

// For tracking input types
typedef enum {
    SCRIPT_FLAVOUR_NONE,
    SCRIPT_FLAVOUR_SINGLESIG,
    SCRIPT_FLAVOUR_OTHER,
    SCRIPT_FLAVOUR_MIXED
} script_flavour_t;

#define WARN_MSG_MIXED_INPUTS "Your inputs in this transaction are of varying types."

#endif /* PROCESS_UTILS_H_ */
