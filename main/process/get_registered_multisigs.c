#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../wallet.h"

#include "process_utils.h"

typedef struct {
    const char* name;
    const char* variant;
    bool sorted;
    bool has_master_blinding_key;
    uint8_t threshold;
    uint8_t num_signers;
    uint8_t master_blinding_key[MULTISIG_MASTER_BLINDING_KEY_SIZE];
} multisig_desc_t;

typedef struct {
    multisig_desc_t multisigs[MAX_MULTISIG_REGISTRATIONS];
    size_t num_multisigs;
} multisig_descriptions_t;

static void reply_registered_multisigs(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const multisig_descriptions_t* descriptions = (const multisig_descriptions_t*)ctx;
    JADE_ASSERT(descriptions->num_multisigs <= sizeof(descriptions->multisigs) / sizeof(descriptions->multisigs[0]));

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_map(container, &root_encoder, descriptions->num_multisigs);
    JADE_ASSERT(cberr == CborNoError);

    for (int i = 0; i < descriptions->num_multisigs; ++i) {
        const multisig_desc_t* const desc = descriptions->multisigs + i;

        cberr = cbor_encode_text_stringz(&root_encoder, desc->name);
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder entry_encoder;
        CborError cberr = cbor_encoder_create_map(&root_encoder, &entry_encoder, 5);
        JADE_ASSERT(cberr == CborNoError);

        add_string_to_map(&entry_encoder, "variant", desc->variant ? desc->variant : "");
        add_boolean_to_map(&entry_encoder, "sorted", desc->sorted);
        add_uint_to_map(&entry_encoder, "threshold", desc->threshold);
        add_uint_to_map(&entry_encoder, "num_signers", desc->num_signers);

        if (desc->has_master_blinding_key) {
            add_bytes_to_map(
                &entry_encoder, "master_blinding_key", desc->master_blinding_key, sizeof(desc->master_blinding_key));
        } else {
            add_bytes_to_map(&entry_encoder, "master_blinding_key", NULL, 0);
        }

        cberr = cbor_encoder_close_container(&root_encoder, &entry_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_registered_multisigs_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_registered_multisigs");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    // Get registered multisig names
    char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_names = sizeof(names) / sizeof(names[0]);
    size_t num_multisigs = 0;
    if (!storage_get_all_multisig_registration_names(names, num_names, &num_multisigs)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to load multisig registrations", NULL);
        goto cleanup;
    }

    // Load description of each
    multisig_descriptions_t descriptions;
    descriptions.num_multisigs = 0;
    JADE_ASSERT(num_multisigs <= sizeof(descriptions.multisigs) / sizeof(descriptions.multisigs[0]));
    for (int i = 0; i < num_multisigs; ++i) {
        const char* errmsg = NULL;
        multisig_data_t multisig_data;
        // NOTE: can extend to pass signer_t structs here if we want full signer details
        const bool valid = multisig_load_from_storage(names[i], &multisig_data, NULL, 0, NULL, &errmsg);

        // If valid for this wallet, add description/summary info
        if (valid) {
            multisig_desc_t* const desc = descriptions.multisigs + descriptions.num_multisigs;
            desc->name = names[i];
            desc->variant = get_script_variant_string(multisig_data.variant);
            desc->sorted = multisig_data.sorted;
            desc->threshold = multisig_data.threshold;
            desc->num_signers = multisig_data.num_xpubs;

            // Optional liquid master blinding key
            if (multisig_data.master_blinding_key_len) {
                JADE_ASSERT(multisig_data.master_blinding_key_len == sizeof(desc->master_blinding_key));
                memcpy(desc->master_blinding_key, multisig_data.master_blinding_key,
                    multisig_data.master_blinding_key_len);
                desc->has_master_blinding_key = true;
            } else {
                desc->has_master_blinding_key = false;
            }

            ++descriptions.num_multisigs;
        } else if (errmsg) {
            // Corrupt or for another wallet - just log and skip
            JADE_LOGD("%s", errmsg);
        }
    }

    // Reply with this info
    const size_t buflen = 256 + (176 * descriptions.num_multisigs);
    uint8_t* const buf = JADE_MALLOC(buflen);
    jade_process_reply_to_message_result(process->ctx, buf, buflen, &descriptions, reply_registered_multisigs);
    free(buf);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
