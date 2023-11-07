#include "../jade_assert.h"
#include "../process.h"
#include "../ui.h"
#include "process_utils.h"

#ifdef CONFIG_IDF_TARGET_ESP32S3
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "attestation/attestation.h"

void sign_attestation_and_send_reply(jade_process_t* process, const uint8_t* challenge, size_t challenge_len);
#endif // CONFIG_IDF_TARGET_ESP32S3

void register_attestation_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_attestation");
    GET_MSG_PARAMS(process);

#ifdef CONFIG_IDF_TARGET_ESP32S3
    char* const privkey_pem = JADE_MALLOC(JADE_ATTEST_RSA_PRIVKEY_PEM_MAX_LEN);
    jade_process_free_on_exit(process, privkey_pem);
    size_t privkey_pem_len = 0;
    rpc_get_string("privkey_pem", JADE_ATTEST_RSA_PRIVKEY_PEM_MAX_LEN, &params, privkey_pem, &privkey_pem_len);
    if (privkey_pem_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid private key from parameters", NULL);
        goto cleanup;
    }

    char ext_pubkey_pem[JADE_ATTEST_RSA_PUBKEY_PEM_MAX_LEN];
    size_t ext_pubkey_pem_len = 0;
    rpc_get_string("ext_pubkey_pem", sizeof(ext_pubkey_pem), &params, ext_pubkey_pem, &ext_pubkey_pem_len);
    if (ext_pubkey_pem_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid external pubkey from parameters", NULL);
        goto cleanup;
    }

    const uint8_t* ext_signature = NULL;
    size_t ext_signature_len = 0;
    rpc_get_bytes_ptr("ext_signature", &params, &ext_signature, &ext_signature_len);
    if (ext_signature_len == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid external signature from parameters", NULL);
        goto cleanup;
    }

    // Step expected to be automated, so no user interaction at this point
    display_processing_message_activity();

    // Initialise attestation parameters
    if (!attestation_initialise(
            privkey_pem, privkey_pem_len, ext_pubkey_pem, ext_pubkey_pem_len, ext_signature, ext_signature_len)) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Failed to initialise attestation parameters", NULL);
        goto cleanup;
    }

    // Success - sign the ext_signature as if it were a challenge
    sign_attestation_and_send_reply(process, ext_signature, ext_signature_len); // sends reply
    JADE_LOGI("Success");

#if defined(CONFIG_BOARD_TYPE_JADE_V2) && !defined(CONFIG_DEBUG_MODE)
    // A production jade unit should reboot after attestation parameters set
    const char* message[] = { "Attestation initialised" };
    display_message_activity(message, 1);
    vTaskDelay(2000 / portTICK_PERIOD_MS);
    esp_restart();
#endif

#else // CONFIG_IDF_TARGET_ESP32S3
    jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Remote attestation not supported", NULL);
    const char* message[] = { "Remote attestation not supported" };
    await_error_activity(message, 1);
#endif // CONFIG_IDF_TARGET_ESP32S3

cleanup:
    return;
}