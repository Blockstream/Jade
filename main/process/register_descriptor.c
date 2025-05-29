#ifndef AMALGAMATED_BUILD
#include "../descriptor.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "process_utils.h"

#include <ctype.h>
#include <sodium/utils.h>

bool show_descriptor_activity(const char* descriptor_name, const descriptor_data_t* descriptor,
    const signer_t* signer_details, size_t num_signer_details, const uint8_t* wallet_fingerprint,
    size_t wallet_fingerprint_len, bool initial_confirmation, bool overwriting, bool is_valid);

// Function to validate descriptor and persist the record
static int register_descriptor(
    const char* descriptor_name, const network_t network_id, descriptor_data_t* descriptor, const char** errmsg)
{
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(descriptor);
    JADE_INIT_OUT_PPTR(errmsg);

    JADE_ASSERT(descriptor->script_len < sizeof(descriptor->script));
    JADE_ASSERT(descriptor->num_values < MAX_ALLOWED_SIGNERS);

    // Not valid for liquid wallets atm
    if (network_is_liquid(network_id)) {
        *errmsg = "Descriptor wallets not supported on liquid network";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Check name valid
    if (!storage_key_name_valid(descriptor_name)) {
        *errmsg = "Invalid descriptor name";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    int retval = 0;
    const size_t registration_len = DESCRIPTOR_BYTES_LEN(descriptor);
    uint8_t* const registration = JADE_MALLOC(registration_len);
    signer_t* const signers = JADE_CALLOC(MAX_ALLOWED_SIGNERS, sizeof(signer_t));
    size_t num_signers = 0;

    // Get signers - this also yields the type
    descriptor_type_t deduced_type = DESCRIPTOR_TYPE_UNKNOWN;
    if (!descriptor_get_signers(descriptor_name, descriptor, network_id, &deduced_type, signers, MAX_ALLOWED_SIGNERS,
            &num_signers, errmsg)) {
        JADE_LOGE("Failed to extract signer information from descriptor");
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }

    // Do not support pure miniscript expressions atm
    if (deduced_type != DESCRIPTOR_TYPE_MIXED) {
        *errmsg = "Pure miniscript expressions not supported";
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }
    descriptor->type = deduced_type;

    // Validate signers - this also yields the type
    size_t total_path_elements = 0; // unused
    const bool allow_string_paths = true; // child paths may be string
    uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(fingerprint, sizeof(fingerprint));
    if (!validate_signers(
            signers, num_signers, allow_string_paths, fingerprint, sizeof(fingerprint), &total_path_elements)) {
        *errmsg = "Failed to validate signers";
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }

    // Validate descriptor by fetching an external and change address
    char* addr0 = NULL;
    char* addr1 = NULL;
    if (!descriptor_to_address(descriptor_name, descriptor, network_id, 0, 0, NULL, &addr0, errmsg)
        || !descriptor_to_address(descriptor_name, descriptor, network_id, 1, 0, NULL, &addr1, errmsg)) {
        // errmsg populated by prior call
        retval = CBOR_RPC_BAD_PARAMETERS;
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_free_string(addr0));
    JADE_WALLY_VERIFY(wally_free_string(addr1));

    if (!descriptor_to_bytes(descriptor, registration, registration_len)) {
        *errmsg = "Failed to serialise descriptor";
        retval = CBOR_RPC_INTERNAL_ERROR;
        goto cleanup;
    }

    // See if a record for this name exists already
    const bool overwriting = storage_descriptor_name_exists(descriptor_name);

    // If so, see if it is identical to the record we are trying to persist
    // - if so, just return true immediately.
    if (overwriting) {
        size_t written = 0;
        uint8_t* const existing = JADE_MALLOC(registration_len);
        if (storage_get_descriptor_registration(descriptor_name, existing, registration_len, &written)
            && written == registration_len && !sodium_memcmp(existing, registration, registration_len)) {
            JADE_LOGI("Descriptor %s: identical registration exists, returning immediately", descriptor_name);
            free(existing);
            goto cleanup;
        }
        free(existing);
    } else {
        // Not overwriting an existing record - check storage slot available
        if (storage_get_descriptor_registration_count() >= MAX_DESCRIPTOR_REGISTRATIONS) {
            *errmsg = "Already have maximum number of descriptor wallets";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }
    }

    // Check to see whether user accepted or declined
    const bool is_valid = true;
    const bool initial_confirmation = true;
    if (!show_descriptor_activity(descriptor_name, descriptor, signers, num_signers, fingerprint, sizeof(fingerprint),
            initial_confirmation, overwriting, is_valid)) {
        JADE_LOGW("User declined to register descriptor");
        *errmsg = "User declined to register descriptor";
        retval = CBOR_RPC_USER_CANCELLED;
        goto cleanup;
    }
    JADE_LOGD("User accepted descriptor");

    // Persist descriptor registration in nvs
    if (!storage_set_descriptor_registration(descriptor_name, registration, registration_len)) {
        *errmsg = "Failed to persist descriptor data";

        const char* message[] = { "Error saving descriptor" };
        await_error_activity(message, 1);
        retval = CBOR_RPC_INTERNAL_ERROR;
        goto cleanup;
    }

cleanup:
    free(signers);
    free(registration);
    return retval;
}

static bool get_data_values(const char* field, const CborValue* value, descriptor_data_t* descriptor)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_ASSERT(descriptor);
    JADE_ASSERT(!descriptor->num_values);

    CborValue result;
    if (!rpc_get_map(field, value, &result)) {
        return false;
    }

    size_t num_map_items = 0;
    if (cbor_value_get_map_length(&result, &num_map_items) != CborNoError || !num_map_items) {
        return false;
    }

    CborValue keyItem;
    CborError cberr = cbor_value_enter_container(&result, &keyItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&keyItem)) {
        return false;
    }

    for (size_t i = 0; i < num_map_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&keyItem));
        string_value_t* const sv = &(descriptor->values[i]);
        CborValue valueItem;

        if (!cbor_value_is_text_string(&keyItem)) {
            return false;
        }

        size_t written = sizeof(sv->key);
        cberr = cbor_value_copy_text_string(&keyItem, sv->key, &written, &valueItem);
        if (cberr != CborNoError || !written || written >= sizeof(sv->key)) {
            return false;
        }
        sv->key_len = (uint8_t)written;

        if (!cbor_value_is_text_string(&valueItem)) {
            return false;
        }

        written = sizeof(sv->value);
        cberr = cbor_value_copy_text_string(&valueItem, sv->value, &written, &keyItem);
        if (cberr != CborNoError || !written || written >= sizeof(sv->value)) {
            return false;
        }
        sv->value_len = (uint16_t)written;
    }

    descriptor->num_values = num_map_items;
    return true;
}

void register_descriptor_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char descriptor_name[MAX_DESCRIPTOR_NAME_SIZE];
    const char* errmsg = NULL;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_descriptor");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    // Get name of descriptor wallet
    size_t written = 0;
    rpc_get_string("descriptor_name", sizeof(descriptor_name), &params, descriptor_name, &written);
    if (written == 0 || !storage_key_name_valid(descriptor_name)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Missing or invalid descriptor name parameter", NULL);
        goto cleanup;
    }

    // Descriptor script and paramaterised values
    descriptor_data_t descriptor = { .script_len = 0, .num_values = 0, .type = DESCRIPTOR_TYPE_UNKNOWN };

    written = 0;
    rpc_get_string("descriptor", sizeof(descriptor.script), &params, descriptor.script, &written);
    if (!written) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid output descriptor string", NULL);
        goto cleanup;
    }
    descriptor.script_len = (uint16_t)written;

    // Signers' keys
    if (!get_data_values("datavalues", &params, &descriptor)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid parameter values", NULL);
        goto cleanup;
    }

    const int errcode = register_descriptor(descriptor_name, network_id, &descriptor, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    // Ok, all verified and persisted
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
