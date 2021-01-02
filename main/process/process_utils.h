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

#endif /* PROCESS_UTILS_H_ */
