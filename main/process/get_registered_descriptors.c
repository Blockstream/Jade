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
    const char* name;
    size_t script_len;
    uint8_t num_values;
} descriptor_desc_t;

typedef struct {
    descriptor_desc_t descriptors[MAX_DESCRIPTOR_REGISTRATIONS];
    size_t num_descriptors;
} descriptor_descriptions_t;

static void reply_registered_descriptors(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const descriptor_descriptions_t* descriptions = (const descriptor_descriptions_t*)ctx;
    JADE_ASSERT(
        descriptions->num_descriptors <= sizeof(descriptions->descriptors) / sizeof(descriptions->descriptors[0]));

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_map(container, &root_encoder, descriptions->num_descriptors);
    JADE_ASSERT(cberr == CborNoError);

    for (int i = 0; i < descriptions->num_descriptors; ++i) {
        const descriptor_desc_t* const desc = descriptions->descriptors + i;

        cberr = cbor_encode_text_stringz(&root_encoder, desc->name);
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder entry_encoder;
        CborError cberr = cbor_encoder_create_map(&root_encoder, &entry_encoder, 2);
        JADE_ASSERT(cberr == CborNoError);

        add_uint_to_map(&entry_encoder, "descriptor_len", desc->script_len);
        add_uint_to_map(&entry_encoder, "num_datavalues", desc->num_values);

        cberr = cbor_encoder_close_container(&root_encoder, &entry_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_registered_descriptors_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_registered_descriptors");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    // Get registered descriptor names
    char names[MAX_DESCRIPTOR_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_descriptors = 0;
    if (!storage_get_all_descriptor_registration_names(names, num_names, &num_descriptors)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to load descriptor registrations");
        goto cleanup;
    }

    // Load description of each
    descriptor_descriptions_t descriptions;
    descriptions.num_descriptors = 0;
    JADE_ASSERT(num_descriptors <= sizeof(descriptions.descriptors) / sizeof(descriptions.descriptors[0]));
    for (int i = 0; i < num_descriptors; ++i) {
        const char* errmsg = NULL;
        descriptor_data_t descriptor_data;
        const bool valid = descriptor_load_from_storage(names[i], &descriptor_data, &errmsg);

        // If valid for this wallet, add description/summary info
        if (valid) {
            descriptor_desc_t* const desc = descriptions.descriptors + descriptions.num_descriptors;
            desc->name = names[i];
            desc->script_len = descriptor_data.script_len;
            desc->num_values = descriptor_data.num_values;
            ++descriptions.num_descriptors;
        } else if (errmsg) {
            // Corrupt or for another wallet - just log and skip
            JADE_LOGD("%s", errmsg);
        }
    }

    // Reply with this info
    const size_t buflen = 256 + (64 * descriptions.num_descriptors);
    uint8_t* const buf = JADE_MALLOC(buflen);
    jade_process_reply_to_message_result(process->ctx, buf, buflen, &descriptions, reply_registered_descriptors);
    free(buf);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
