#ifndef AMALGAMATED_BUILD
#include "../descriptor.h"
#include "../jade_assert.h"
#include "../process.h"
#include "../storage.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../wallet.h"

#include "process_utils.h"

typedef struct {
    const char* descriptor_name;
    descriptor_data_t* descriptor_data;
} descriptor_details_t;

static void reply_registered_descriptor(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const descriptor_details_t* descriptor_details = (const descriptor_details_t*)ctx;
    JADE_ASSERT(descriptor_details->descriptor_name);
    JADE_ASSERT(descriptor_details->descriptor_data);

    const descriptor_data_t* descriptor_data = descriptor_details->descriptor_data;
    JADE_ASSERT(descriptor_data->num_values <= MAX_ALLOWED_SIGNERS);

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_map(container, &root_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);

    JADE_ASSERT(storage_key_name_valid(descriptor_details->descriptor_name));
    add_string_to_map(&root_encoder, "descriptor_name", descriptor_details->descriptor_name);

    JADE_ASSERT(descriptor_data->script);
    JADE_ASSERT(descriptor_data->script[descriptor_data->script_len] == '\0');
    add_string_to_map(&root_encoder, "descriptor", descriptor_data->script);

    // Signer/placeholder value details
    cberr = cbor_encode_text_stringz(&root_encoder, "datavalues");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder values_encoder;
    cberr = cbor_encoder_create_map(&root_encoder, &values_encoder, descriptor_data->num_values);
    JADE_ASSERT(cberr == CborNoError);

    for (int i = 0; i < descriptor_data->num_values; ++i) {
        const string_value_t* datavalue = descriptor_data->values + i;
        JADE_ASSERT(datavalue->key_len);
        JADE_ASSERT(datavalue->key[datavalue->key_len] == '\0');
        JADE_ASSERT(datavalue->value_len);
        JADE_ASSERT(datavalue->value[datavalue->value_len] == '\0');
        add_string_to_map(&values_encoder, datavalue->key, datavalue->value);
    }

    cberr = cbor_encoder_close_container(&root_encoder, &values_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_registered_descriptor_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char descriptor_name[MAX_DESCRIPTOR_NAME_SIZE];
    size_t written;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_registered_descriptor");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // Get name of descriptor wallet
    written = 0;
    rpc_get_string("descriptor_name", sizeof(descriptor_name), &params, descriptor_name, &written);
    if (written == 0 || !storage_key_name_valid(descriptor_name)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Missing or invalid descriptor name parameter", NULL);
        goto cleanup;
    }

    const char* errmsg = NULL;
    descriptor_data_t descriptor_data;

    // Load descriptor record from storage
    if (!descriptor_load_from_storage(descriptor_name, &descriptor_data, &errmsg)) {
        // Doesn't exist, corrupt or for another wallet
        JADE_LOGW("%s", errmsg);
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Named descriptor wallet does not exist for this signer", NULL);
        goto cleanup;
    }

    // Reply with this info
    const size_t buflen = 1024 + (128 * descriptor_data.num_values);
    uint8_t* const buf = JADE_MALLOC(buflen);
    const descriptor_details_t descriptor_details
        = { .descriptor_name = descriptor_name, .descriptor_data = &descriptor_data };
    jade_process_reply_to_message_result(process->ctx, buf, buflen, &descriptor_details, reply_registered_descriptor);
    free(buf);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
