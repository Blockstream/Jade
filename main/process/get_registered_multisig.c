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
    const char* multisig_name;
    const char* multisig_export_file;
    multisig_data_t* multisig_data;
    signer_t* signer_details;
} multisig_details_t;

static void reply_registered_multisig(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const multisig_details_t* multisig_details = (const multisig_details_t*)ctx;
    JADE_ASSERT(multisig_details->multisig_name);
    // multisig_export_file is optional
    JADE_ASSERT(multisig_details->multisig_data);
    JADE_ASSERT(multisig_details->signer_details);

    const multisig_data_t* multisig_data = multisig_details->multisig_data;
    JADE_ASSERT(multisig_data->num_xpubs <= MAX_ALLOWED_SIGNERS);

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_map(container, &root_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    JADE_ASSERT(storage_key_name_valid(multisig_details->multisig_name));
    add_string_to_map(&root_encoder, "multisig_name", multisig_details->multisig_name);

    if (multisig_details->multisig_export_file) {
        // Flat-file export reply
        add_string_to_map(&root_encoder, "multisig_file", multisig_details->multisig_export_file);
    } else {
        // Structured json reply
        cberr = cbor_encode_text_stringz(&root_encoder, "descriptor");
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder entry_encoder;
        cberr = cbor_encoder_create_map(&root_encoder, &entry_encoder, 5);
        JADE_ASSERT(cberr == CborNoError);

        const char* variant = get_script_variant_string(multisig_data->variant);
        add_string_to_map(&entry_encoder, "variant", variant ? variant : "");
        add_boolean_to_map(&entry_encoder, "sorted", multisig_data->sorted);
        add_uint_to_map(&entry_encoder, "threshold", multisig_data->threshold);

        JADE_ASSERT(!multisig_data->master_blinding_key_len
            || multisig_data->master_blinding_key_len == sizeof(multisig_data->master_blinding_key));
        add_bytes_to_map(&entry_encoder, "master_blinding_key", multisig_data->master_blinding_key,
            multisig_data->master_blinding_key_len);

        // Signer details
        cberr = cbor_encode_text_stringz(&entry_encoder, "signers");
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder signers_encoder;
        cberr = cbor_encoder_create_array(&entry_encoder, &signers_encoder, multisig_data->num_xpubs);
        JADE_ASSERT(cberr == CborNoError);

        for (int i = 0; i < multisig_data->num_xpubs; ++i) {
            const signer_t* signer = multisig_details->signer_details + i;
            JADE_ASSERT(signer->xpub_len);
            JADE_ASSERT(signer->xpub[signer->xpub_len] == '\0');

            CborEncoder signer_encoder;
            cberr = cbor_encoder_create_map(&signers_encoder, &signer_encoder, 4);
            JADE_ASSERT(cberr == CborNoError);

            add_bytes_to_map(&signer_encoder, "fingerprint", signer->fingerprint, sizeof(signer->fingerprint));
            add_uint_array_to_map(&signer_encoder, "derivation", signer->derivation, signer->derivation_len);
            add_string_to_map(&signer_encoder, "xpub", signer->xpub);

            // String paths not support for export
            if (!signer->path_is_string) {
                add_uint_array_to_map(&signer_encoder, "path", signer->path, signer->path_len);
            } else {
                add_uint_array_to_map(&signer_encoder, "path", NULL, 0);
            }

            cberr = cbor_encoder_close_container(&signers_encoder, &signer_encoder);
            JADE_ASSERT(cberr == CborNoError);
        }

        cberr = cbor_encoder_close_container(&entry_encoder, &signers_encoder);
        JADE_ASSERT(cberr == CborNoError);

        cberr = cbor_encoder_close_container(&root_encoder, &entry_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_registered_multisig_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char multisig_name[MAX_MULTISIG_NAME_SIZE];
    size_t written;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_registered_multisig");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // Get name of multisig wallet
    written = 0;
    rpc_get_string("multisig_name", sizeof(multisig_name), &params, multisig_name, &written);
    if (written == 0 || !storage_key_name_valid(multisig_name)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Missing or invalid multisig name parameter");
        goto cleanup;
    }

    bool asfile = false;
    if (rpc_has_field_data("as_file", &params)) {
        if (!rpc_get_boolean("as_file", &params, &asfile)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid as_file parameter");
            goto cleanup;
        }
    }

    const char* errmsg = NULL;
    multisig_data_t multisig_data;
    signer_t* const signer_details = JADE_CALLOC(MAX_ALLOWED_SIGNERS, sizeof(signer_t));
    jade_process_free_on_exit(process, signer_details);

    // Load multisig record from storage
    written = 0;
    if (!multisig_load_from_storage(
            multisig_name, &multisig_data, signer_details, MAX_ALLOWED_SIGNERS, &written, &errmsg)) {
        // Doesn't exist, corrupt or for another wallet
        JADE_LOGW("%s", errmsg);
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Named multisig wallet does not exist for this signer");
        goto cleanup;
    }
    JADE_ASSERT(written <= MAX_ALLOWED_SIGNERS);

    if (written != multisig_data.num_xpubs) {
        JADE_LOGW("Unable to export multisig details - no signer details");
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Named multisig too old include detailed signer data");
        goto cleanup;
    }

    // Exists and valid for this wallet
    // If flat-file requested, produce that now
    char* export_file = NULL;
    if (asfile) {
        const size_t export_file_len = MULTISIG_FILE_MAX_LEN(multisig_data.num_xpubs);
        export_file = JADE_MALLOC(export_file_len);
        jade_process_free_on_exit(process, export_file);

        written = 0;
        if (!multisig_create_export_file(multisig_name, &multisig_data, signer_details, multisig_data.num_xpubs,
                export_file, export_file_len, &written)
            || !written || written > export_file_len) {
            JADE_LOGE("Failed to produce multisig export file");
            jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to produce multisig export file");
            goto cleanup;
        }
    }

    // Reply with this info
    const size_t buflen = 1024 + (128 * multisig_data.num_xpubs);
    uint8_t* const buf = JADE_MALLOC(buflen);
    const multisig_details_t multisig_details = { .multisig_name = multisig_name,
        .multisig_export_file = export_file,
        .multisig_data = &multisig_data,
        .signer_details = signer_details };
    jade_process_reply_to_message_result(process->ctx, buf, buflen, &multisig_details, reply_registered_multisig);
    free(buf);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
