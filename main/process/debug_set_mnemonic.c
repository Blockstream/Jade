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
    char passphrase[PASSPHRASE_MAX_LEN + 1];
    SENSITIVE_PUSH(passphrase, sizeof(passphrase));
    const char* p_passphrase = NULL;
    bool temporary_wallet = false;
    const uint8_t* seed = NULL;
    size_t written = 0;

    keychain_t keydata = { 0 };
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // Get field which can be set to test 'temporary restore' wallet
    rpc_get_boolean("temporary_wallet", &params, &temporary_wallet);

    // Slightly hacky, can accept a seed or a mnemonic
    if (rpc_has_field_data("seed", &params)) {
        rpc_get_bytes_ptr("seed", &params, &seed, &written);
        if (written != 32 && written != 64) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid seed length", NULL);
            goto cleanup;
        }
        keychain_derive_from_seed(seed, written, &keydata);

        // A 'seed' wallet is implicitly always a 'temporary' wallet
        // (as we have no mnemonic entropy to persist)
        temporary_wallet = true;
    } else {
        // Cannot use rpc_get_string_ptr here unfortunately because the resulting string
        // is not nul terminated and we need a nul terminated string to pass to wally
        rpc_get_string("mnemonic", sizeof(mnemonic), &params, mnemonic, &written);
        if (written == 0) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract mnemonic or seed from parameters", NULL);
            goto cleanup;
        }

        if (rpc_has_field_data("passphrase", &params)) {
            written = 0;
            rpc_get_string("passphrase", sizeof(passphrase), &params, passphrase, &written);
            if (written == 0 || written > PASSPHRASE_MAX_LEN) {
                jade_process_reject_message(
                    process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid passphrase from parameters", NULL);
                goto cleanup;
            }
            p_passphrase = passphrase;
        }

        if (!keychain_derive_from_mnemonic(mnemonic, p_passphrase, &keydata)) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to derive keychain from mnemonic", NULL);
            goto cleanup;
        }
    }

    // Copy temporary keychain into a new global keychain
    // and remove the restriction on network-types.
    keychain_set(&keydata, (uint8_t)process->ctx.source, temporary_wallet);
    keychain_clear_network_type_restriction();

    // To be consistent with normal wallet setup in mnemonic.c ...
    if (!temporary_wallet) {
        JADE_ASSERT(!seed);

        // We need to cache the root mnemonic entropy as it is this that we will persist
        // encrypted to local flash (requiring a passphrase to derive the wallet master key).
        keychain_cache_mnemonic_entropy(mnemonic);
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(passphrase);
    SENSITIVE_POP(mnemonic);
    return;
}
