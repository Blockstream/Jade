
#include "../jade_assert.h"
#include "../process.h"
#include "../rsa.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"

#include "process_utils.h"

typedef struct {
    rsa_signature_t* signatures;
    size_t num_signatures;
} signatures_t;

static void reply_signatures(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    const signatures_t* signatures = (const signatures_t*)ctx;

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_array(container, &root_encoder, signatures->num_signatures);
    JADE_ASSERT(cberr == CborNoError);

    for (int i = 0; i < signatures->num_signatures; ++i) {
        const rsa_signature_t* const signature = signatures->signatures + i;
        cberr = cbor_encode_byte_string(&root_encoder, signature->signature, signature->signature_len);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

static void get_digests_allocate(
    const char* field, const CborValue* value, rsa_signing_digest_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_INIT_OUT_PPTR(data);
    JADE_INIT_OUT_SIZE(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t num_array_items = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_array_items);
    if (cberr != CborNoError || !num_array_items) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    rsa_signing_digest_t* const digests = JADE_CALLOC(num_array_items, sizeof(rsa_signing_digest_t));

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        rsa_signing_digest_t* const digest = digests + i;

        const uint8_t* data = NULL;
        size_t data_len = 0;
        rpc_get_raw_bytes_ptr(&arrayItem, &data, &data_len);
        if (!data || data_len != sizeof(digest->digest)) {
            free(digests);
            return;
        }

        memcpy(digest->digest, data, data_len);
        digest->digest_len = data_len;

        cberr = cbor_value_advance(&arrayItem);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(digests);
        return;
    }

    *written = num_array_items;
    *data = digests;
}

void sign_bip85_digests_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "sign_bip85_digests");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    const char* errmsg = NULL;
    size_t key_bits = 0;
    size_t index = 0;

    if (!params_get_bip85_rsa_key(&params, &key_bits, &index, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    // Copy digest data
    rsa_signing_digest_t* digests = NULL;
    size_t num_digests = 0;
    get_digests_allocate("digests", &params, &digests, &num_digests);

    if (num_digests == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract digests from parameters", NULL);
        goto cleanup;
    }

    JADE_ASSERT(digests);
    jade_process_free_on_exit(process, digests);

    const size_t max_digests = key_bits <= 2048 ? 8 : key_bits < 4096 ? 6 : 4;
    if (num_digests > max_digests) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Unsupported number of digests", NULL);
        goto cleanup;
    }

    // User to confirm signing
    int ret;
    char buf1[20], buf2[24], buf3[32];
    if (num_digests > 1) {
        ret = snprintf(buf1, sizeof(buf1), "Sign %u digests", num_digests);
    } else {
        ret = snprintf(buf1, sizeof(buf1), "Sign passed digest");
    }
    JADE_ASSERT(ret > 0 && ret < sizeof(buf1));
    ret = snprintf(buf2, sizeof(buf2), "with %u-bit key", key_bits);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf2));
    ret = snprintf(buf3, sizeof(buf3), "index: %u?", index);
    JADE_ASSERT(ret > 0 && ret < sizeof(buf3));

    const char* message[] = { buf1, buf2, buf3 };
    if (!await_yesno_activity("BIPI85 RSA Signing", message, 3, true, "blkstrm.com/bip85rsa")) {
        JADE_LOGW("User declined to sign digests with BIP85 key");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to sign digests", NULL);
        goto cleanup;
    }
    JADE_LOGD("User pressed accept");

    display_processing_message_activity();

    // Allocate signature data
    rsa_signature_t* const signatures = JADE_CALLOC(num_digests, sizeof(rsa_signature_t));
    jade_process_free_on_exit(process, signatures);

    if (!rsa_bip85_key_sign_digests(key_bits, index, digests, num_digests, signatures, num_digests)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to generate RSA signatures", NULL);
        goto cleanup;
    }

    // Reply with signatures
    const signatures_t result = { .signatures = signatures, .num_signatures = num_digests };
    jade_process_reply_to_message_result(process->ctx, &result, reply_signatures);
    JADE_LOGI("Success");

cleanup:
    return;
}
