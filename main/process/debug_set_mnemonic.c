#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../utils/cbor_rpc.h"

#include <cbor.h>
#include <wally_bip39.h>

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
    SENSITIVE_PUSH(mnemonic, sizeof(mnemonic));
    const uint8_t* seed;
    size_t written = 0;

    keychain_t keydata;
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // Slightly hacky, can accept a seed or a mnemonic
    rpc_get_bytes_ptr("seed", &params, &seed, &written);
    if (written > 0) {
        if (written != 32 && written != 64) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid seed length", NULL);
            goto cleanup;
        }
        keychain_derive_from_seed(seed, written, &keydata);
    } else {
        // Cannot use rpc_get_string_ptr here unfortunately because the resulting string
        // is not null-terminated and we need a null terminated string to pass to wally
        rpc_get_string("mnemonic", sizeof(mnemonic), &params, mnemonic, &written);
        if (written > 0) {
            if (!keychain_derive(mnemonic, &keydata)) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to derive keychain from mnemonic", mnemonic);
                goto cleanup;
            }
        } else {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract mnemonic or seed from parameters", NULL);
            goto cleanup;
        }
    }

    // Copy temporary keychain into a new global keychain
    // and remove the restriction on network-types.
    keychain_set(&keydata, (uint8_t)process->ctx.source);

    // Remove the restriction on network-types.
    keychain_clear_network_type_restriction();

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(mnemonic);
    return;
}
