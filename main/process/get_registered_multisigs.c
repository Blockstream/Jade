#include "../jade_assert.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include "process_utils.h"

typedef struct {
    const char* name;
    const char* variant;
    bool sorted;
    uint8_t threshold;
    uint8_t num_signers;
} multisig_desc_t;

typedef struct {
    multisig_desc_t multisigs[MAX_MULTISIG_REGISTRATIONS];
    size_t multisigs_len;
} multisig_descriptions_t;

static void reply_registered_multisigs(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const multisig_descriptions_t* descriptions = (const multisig_descriptions_t*)ctx;
    JADE_ASSERT(descriptions->multisigs_len <= sizeof(descriptions->multisigs) / sizeof(descriptions->multisigs[0]));

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_map(container, &root_encoder, descriptions->multisigs_len);
    JADE_ASSERT(cberr == CborNoError);

    for (int i = 0; i < descriptions->multisigs_len; ++i) {
        const multisig_desc_t* const desc = descriptions->multisigs + i;

        cberr = cbor_encode_text_stringz(&root_encoder, desc->name);
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder entry_encoder;
        CborError cberr = cbor_encoder_create_map(&root_encoder, &entry_encoder, 4);
        JADE_ASSERT(cberr == CborNoError);

        add_string_to_map(&entry_encoder, "variant", desc->variant ? desc->variant : "");
        add_boolean_to_map(&entry_encoder, "sorted", desc->sorted);
        add_uint_to_map(&entry_encoder, "threshold", desc->threshold);
        add_uint_to_map(&entry_encoder, "num_signers", desc->num_signers);

        cberr = cbor_encoder_close_container(&root_encoder, &entry_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_registered_multisigs_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_registered_multisigs");

    // Get registered multisig names
    char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t names_len = sizeof(names) / sizeof(names[0]);
    size_t num_multisigs = 0;
    if (!storage_get_all_multisig_registration_names(names, names_len, &num_multisigs)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to load multisig registrations", NULL);
        goto cleanup;
    }

    // Load description of each
    multisig_descriptions_t descriptions;
    descriptions.multisigs_len = 0;
    JADE_ASSERT(num_multisigs <= sizeof(descriptions.multisigs) / sizeof(descriptions.multisigs[0]));

    for (int i = 0; i < num_multisigs; ++i) {
        const char* errmsg = NULL;
        multisig_data_t multisig_data;
        const bool valid = multisig_load_from_storage(names[i], &multisig_data, &errmsg);

        // If valid for this wallet, add description info (name, script-variant, is-sorted, threshold, num-signers)
        if (valid) {
            multisig_desc_t* const desc = descriptions.multisigs + descriptions.multisigs_len;
            desc->name = names[i];
            desc->variant = get_script_variant_string(multisig_data.variant);
            desc->sorted = multisig_data.sorted;
            desc->threshold = multisig_data.threshold;
            desc->num_signers = multisig_data.xpubs_len;
            ++descriptions.multisigs_len;
        } else if (errmsg) {
            // Corrupt or for another wallet - just log and skip
            JADE_LOGD("%s", errmsg);
        }
    }

    // Reply with this info
    jade_process_reply_to_message_result(process->ctx, &descriptions, reply_registered_multisigs);

cleanup:
    return;
}
