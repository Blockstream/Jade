
#include "../jade_assert.h"
#include "../process.h"
#include "../rsa.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "process_utils.h"

void get_bip85_pubkey_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_bip85_pubkey");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    const char* errmsg = NULL;
    size_t key_bits = 0;
    size_t index = 0;

    if (!params_get_bip85_rsa_key(&params, &key_bits, &index, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg, NULL);
        goto cleanup;
    }

    display_processing_message_activity();

    char pubkey_pem[1024];
    if (!rsa_get_bip85_pubkey_pem(key_bits, index, pubkey_pem, sizeof(pubkey_pem))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to generate RSA key", NULL);
        goto cleanup;
    }

    // Reply with the pubkey pem
    jade_process_reply_to_message_result(process->ctx, pubkey_pem, cbor_result_string_cb);
    JADE_LOGI("Success");

cleanup:
    return;
}
