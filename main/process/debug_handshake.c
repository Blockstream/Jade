#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"

#include <sodium/crypto_verify_32.h>
#include <sodium/crypto_verify_64.h>
#include <sodium/utils.h>

#include "process_utils.h"

// Pinserver interaction functions as used in menmonic.c and pin.c
bool pinclient_savekeys(jade_process_t* process, const uint8_t* pin, size_t pin_size, const keychain_t* keydata);
bool pinclient_loadkeys(jade_process_t* process, const uint8_t* pin, size_t pin_size, keychain_t* keydata);

static void fake_auth_msg_request(jade_process_t* process, uint8_t* process_cbor, size_t process_cbor_len)
{
    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, process_cbor, process_cbor_len, 0);
    CborEncoder root_map_encoder; // id, method
    CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);
    const char* id;
    size_t size = 0;
    rpc_get_string_ptr("id", &process->ctx.value, &id, &size);
    JADE_ASSERT(size != 0);
    add_string_sized_to_map(&root_map_encoder, "id", id, size);
    add_string_to_map(&root_map_encoder, "method", "auth_user");
    cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
    JADE_ASSERT(cberr == CborNoError);
    if (process->ctx.cbor) {
        free(process->ctx.cbor);
    }
    process->ctx.cbor = process_cbor;
    process->ctx.cbor_len = cbor_encoder_get_buffer_size(&root_encoder, process_cbor);

    // reinit value, parser with new values
    cberr = cbor_parser_init(
        process->ctx.cbor, process->ctx.cbor_len, CborValidateBasic, &process->ctx.parser, &process->ctx.value);
    JADE_ASSERT(cberr == CborNoError);
}

// NOTE: this is purely a test case.
// It is tightly coupled with the test case: test_handshake() in test_jade.py
void debug_handshake(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());

    jade_process_t* process = process_ptr;
    ASSERT_CURRENT_MESSAGE(process, "debug_handshake");

    uint8_t user_pin[] = { 0, 1, 2, 3, 4, 5 };

    keychain_t keydata;
    keychain_t keydata_decrypted;
    SENSITIVE_PUSH(&keydata, sizeof(keydata));
    SENSITIVE_PUSH(&keydata_decrypted, sizeof(keydata_decrypted));

    char* mnemonic = NULL;
    keychain_get_new_mnemonic(&mnemonic, 24);
    JADE_ASSERT(mnemonic);
    SENSITIVE_PUSH(mnemonic, strlen(mnemonic));
    const bool test_res = keychain_derive(mnemonic, NULL, &keydata);
    JADE_ASSERT(test_res);
    SENSITIVE_POP(mnemonic);
    wally_free_string(mnemonic);

    // Create a temp process with the message type to 'auth_user' so we can send it through the
    // proper codepath which is expecting to be triggered by one of those.
    // A bit hacky, but hey, this is a test! ;-)
    uint8_t* process_cbor = JADE_MALLOC(256);
    fake_auth_msg_request(process, process_cbor, 256);

    // Test setting a new pin using the 'real' pinserver interaction code
    if (!pinclient_savekeys(process, user_pin, sizeof(user_pin), &keydata)) {
        JADE_LOGE("pinclient_savekeys() failed");
        goto cleanup;
    }

    JADE_ASSERT(keychain_has_pin());
    JADE_ASSERT(storage_get_counter() == 3);
    JADE_LOGI("Set Success");

    // Wait for another debug message and update the type again
    jade_process_load_in_message(process, true);
    ASSERT_CURRENT_MESSAGE(process, "debug_handshake");

    process_cbor = JADE_MALLOC(256);
    fake_auth_msg_request(process, process_cbor, 256);

    // Test get pin again using the 'real' pinserver interaction code.
    if (!pinclient_loadkeys(process, user_pin, sizeof(user_pin), &keydata_decrypted)) {
        JADE_LOGE("pinclient_loadkeys() failed");
        goto cleanup;
    }

    // Check the keys match that from the 'set' steps above and the keychain
    int res = sodium_memcmp(&keydata.xpriv, &keydata_decrypted.xpriv, sizeof(struct ext_key));
    JADE_ASSERT(res == 0);
    res = crypto_verify_64(keydata.service_path, keydata_decrypted.service_path);
    JADE_ASSERT(res == 0);
    res = crypto_verify_64(keydata.master_unblinding_key, keydata_decrypted.master_unblinding_key);
    JADE_ASSERT(res == 0);

    JADE_ASSERT(keychain_has_pin());
    JADE_ASSERT(storage_get_counter() == 3);
    JADE_LOGI("Get Success");

cleanup:
    SENSITIVE_POP(&keydata_decrypted);
    SENSITIVE_POP(&keydata);
}
