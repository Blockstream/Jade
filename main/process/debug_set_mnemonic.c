#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../utils/cbor_rpc.h"

#include <cbor.h>
#include <string.h>

#include "process_utils.h"

#define LONGEST_WORD 9
#define NUM_OF_WORDS 24
#define NULLSTRING 1
#define MAX_MNEMONIC_LEN (LONGEST_WORD * NUM_OF_WORDS + NULLSTRING)

void debug_set_mnemonic_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "debug_set_mnemonic");

    GET_MSG_PARAMS(process);

    char mnemonic[MAX_MNEMONIC_LEN];
    size_t written = 0;

    rpc_get_string("mnemonic", sizeof(mnemonic), &params, mnemonic, &written);

    if (written == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract mnemonic from parameters", NULL);
        return;
    }

    struct keychain_handle khandle;
    const bool retval = keychain_derive(mnemonic, &khandle);
    if (!retval) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to derive keychain from mnemonic", mnemonic);
        return;
    }
    SENSITIVE_PUSH(&khandle, sizeof(khandle));

    // Copy temporary keychain into a new global keychain
    // and remove the restriction on network-types.
    set_keychain(&khandle);
    SENSITIVE_POP(&khandle);

    keychain_clear_network_type_restriction();

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
