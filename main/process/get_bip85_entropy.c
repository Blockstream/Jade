#include "../aes.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../process.h"
#include "../random.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include "process_utils.h"

static const unsigned char HMAC_BIP39_MESSAGE[]
    = { 'b', 'i', 'p', '8', '5', '_', 'b', 'i', 'p', '3', '9', '_', 'e', 'n', 't', 'r', 'o', 'p', 'y' };
static const unsigned char HMAC_RSA_MESSAGE[]
    = { 'b', 'i', 'p', '8', '5', '_', 'r', 's', 'a', '_', 'e', 'n', 't', 'r', 'o', 'p', 'y' };

#define RSA_KEY_SIZE_VALID(bits) (bits == 1024 || bits == 2048 || bits == 3072 || bits == 4096 || bits == 8192)

typedef struct {
    uint8_t encrypted[AES_ENCRYPTED_LEN(HMAC_SHA512_LEN) + HMAC_SHA256_LEN];
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    size_t encrypted_len;
} bip85_data_t;

void await_qr_help_activity(const char* url);

static void populate_bip85_reply_data(CborEncoder* container, const bip85_data_t* bip85_data)
{
    JADE_ASSERT(container);
    JADE_ASSERT(bip85_data);
    JADE_ASSERT(bip85_data->encrypted_len);

    CborEncoder map_encoder; // result data
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "pubkey", bip85_data->pubkey, sizeof(bip85_data->pubkey));
    add_bytes_to_map(&map_encoder, "encrypted", bip85_data->encrypted, bip85_data->encrypted_len);

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

static void reply_bip85_data(const void* ctx, CborEncoder* container)
{
    const bip85_data_t* const bip85_data = (const bip85_data_t*)ctx;
    populate_bip85_reply_data(container, bip85_data);
}

static bool get_encrypted_bip85_bip39_entropy(const size_t nwords, const size_t index, const uint8_t* pubkey,
    const size_t pubkey_len, bip85_data_t* bip85_data, const char** errmsg)
{
    JADE_ASSERT(nwords);
    // index can be 0
    JADE_ASSERT(pubkey);
    JADE_ASSERT(pubkey_len == EC_PUBLIC_KEY_LEN);
    JADE_ASSERT(bip85_data);
    JADE_INIT_OUT_PPTR(errmsg);

    uint8_t eph_privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(eph_privkey, sizeof(eph_privkey));
    uint8_t entropy[HMAC_SHA512_LEN];
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    bool retval = false;

    // Get a new ephemeral key and store the pubkey in the output struct
    if (!keychain_get_new_privatekey(eph_privkey, sizeof(eph_privkey))) {
        *errmsg = "Failed to generate new ephemeral key";
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_ec_public_key_from_private_key(
        eph_privkey, sizeof(eph_privkey), bip85_data->pubkey, sizeof(bip85_data->pubkey)));

    // Generate the bip85/bip39 entropy
    size_t entropy_len = 0;
    wallet_get_bip85_bip39_entropy(nwords, index, entropy, sizeof(entropy), &entropy_len);
    if (!entropy_len || entropy_len > sizeof(entropy)) {
        *errmsg = "Failed to calculate bip85 entropy from parameters";
        goto cleanup;
    }

    // Use wally call to produce encrypted/hmac'd blob
    uint8_t iv[AES_BLOCK_LEN];
    get_random(iv, sizeof(iv));
    if (wally_aes_cbc_with_ecdh_key(eph_privkey, sizeof(eph_privkey), iv, sizeof(iv), entropy, entropy_len, pubkey,
            pubkey_len, HMAC_BIP39_MESSAGE, sizeof(HMAC_BIP39_MESSAGE), AES_FLAG_ENCRYPT, bip85_data->encrypted,
            sizeof(bip85_data->encrypted), &bip85_data->encrypted_len)
            != WALLY_OK
        || bip85_data->encrypted_len > sizeof(bip85_data->encrypted)) {
        *errmsg = "Failed to encrypt bip85 entropy";
        goto cleanup;
    }

    retval = true;
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(eph_privkey);
    return retval;
}

static bool get_encrypted_bip85_rsa_entropy(const size_t key_bits, const size_t index, const uint8_t* pubkey,
    const size_t pubkey_len, bip85_data_t* bip85_data, const char** errmsg)
{
    JADE_ASSERT(key_bits);
    // index can be 0
    JADE_ASSERT(pubkey);
    JADE_ASSERT(pubkey_len == EC_PUBLIC_KEY_LEN);
    JADE_ASSERT(bip85_data);
    JADE_INIT_OUT_PPTR(errmsg);

    uint8_t eph_privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(eph_privkey, sizeof(eph_privkey));
    uint8_t entropy[HMAC_SHA512_LEN];
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    bool retval = false;

    // Get a new ephemeral key and store the pubkey in the output struct
    if (!keychain_get_new_privatekey(eph_privkey, sizeof(eph_privkey))) {
        *errmsg = "Failed to generate new ephemeral key";
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_ec_public_key_from_private_key(
        eph_privkey, sizeof(eph_privkey), bip85_data->pubkey, sizeof(bip85_data->pubkey)));

    // Generate the bip85/bip39 entropy
    size_t entropy_len = 0;
    wallet_get_bip85_rsa_entropy(key_bits, index, entropy, sizeof(entropy), &entropy_len);
    if (!entropy_len || entropy_len > sizeof(entropy)) {
        *errmsg = "Failed to calculate bip85 entropy from parameters";
        goto cleanup;
    }

    // Use wally call to produce encrypted/hmac'd blob
    uint8_t iv[AES_BLOCK_LEN];
    get_random(iv, sizeof(iv));
    if (wally_aes_cbc_with_ecdh_key(eph_privkey, sizeof(eph_privkey), iv, sizeof(iv), entropy, entropy_len, pubkey,
            pubkey_len, HMAC_RSA_MESSAGE, sizeof(HMAC_RSA_MESSAGE), AES_FLAG_ENCRYPT, bip85_data->encrypted,
            sizeof(bip85_data->encrypted), &bip85_data->encrypted_len)
            != WALLY_OK
        || bip85_data->encrypted_len > sizeof(bip85_data->encrypted)) {
        *errmsg = "Failed to encrypt bip85 entropy";
        goto cleanup;
    }

    retval = true;
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(eph_privkey);
    return retval;
}

static int get_bip85_bip39_entropy_data(const CborValue* params, bip85_data_t* bip85_data, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(bip85_data);
    JADE_INIT_OUT_PPTR(errmsg);

    // Get number of words and final index
    size_t nwords = 0;
    if (!rpc_get_sizet("num_words", params, &nwords) || (nwords != 12 && nwords != 24)) {
        *errmsg = "Failed to fetch valid number of words from message";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    size_t index = 0;
    if (!rpc_get_sizet("index", params, &index)) {
        *errmsg = "Failed to fetch valid index from message";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    const uint8_t* pubkey = NULL;
    size_t pubkey_len = 0;
    rpc_get_bytes_ptr("pubkey", params, &pubkey, &pubkey_len);
    if (pubkey_len != EC_PUBLIC_KEY_LEN) {
        *errmsg = "Failed to fetch valid pubkey from message";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // User to confirm
    char nwordphrase[24];
    int ret = snprintf(nwordphrase, sizeof(nwordphrase), "%u word seed phrase", nwords);
    JADE_ASSERT(ret > 0 && ret < sizeof(nwordphrase));

    char txtindex[24];
    ret = snprintf(txtindex, sizeof(txtindex), "for BIP85 index %u?", index);
    JADE_ASSERT(ret > 0 && ret < sizeof(txtindex));

    const char* message[] = { "Export an encrypted", nwordphrase, txtindex };

    if (!await_continueback_activity("Key Export", message, 3, false, "blkstrm.com/bip85")) {
        // User declined
        *errmsg = "User declined to export entropy";
        return CBOR_RPC_USER_CANCELLED;
    }

    // Calculate encrypted entropy
    if (!get_encrypted_bip85_bip39_entropy(nwords, index, pubkey, pubkey_len, bip85_data, errmsg)) {
        // errmsg populated
        return CBOR_RPC_INTERNAL_ERROR;
    }

    // Success!
    return 0;
}

static int get_bip85_rsa_entropy_data(const CborValue* params, bip85_data_t* bip85_data, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(bip85_data);
    JADE_INIT_OUT_PPTR(errmsg);

    // Get number of key_bits and final index
    size_t key_bits = 0;
    if (!rpc_get_sizet("key_bits", params, &key_bits) || !RSA_KEY_SIZE_VALID(key_bits)) {
        *errmsg = "Failed to fetch valid number of key_bits from message";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    size_t index = 0;
    if (!rpc_get_sizet("index", params, &index)) {
        *errmsg = "Failed to fetch valid index from message";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    const uint8_t* pubkey = NULL;
    size_t pubkey_len = 0;
    rpc_get_bytes_ptr("pubkey", params, &pubkey, &pubkey_len);
    if (pubkey_len != EC_PUBLIC_KEY_LEN) {
        *errmsg = "Failed to fetch valid pubkey from message";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // User to confirm
    char nwordphrase[24];
    int ret = snprintf(nwordphrase, sizeof(nwordphrase), "%u rsa key size", key_bits);
    JADE_ASSERT(ret > 0 && ret < sizeof(nwordphrase));

    char txtindex[24];
    ret = snprintf(txtindex, sizeof(txtindex), "for BIP85 index %u?", index);
    JADE_ASSERT(ret > 0 && ret < sizeof(txtindex));

    const char* message[] = { "Export an encrypted", nwordphrase, txtindex };

    if (!await_continueback_activity("Key Export", message, 3, false, "blkstrm.com/bip85")) {
        // User declined
        *errmsg = "User declined to export entropy";
        return CBOR_RPC_USER_CANCELLED;
    }

    // Calculate encrypted entropy
    if (!get_encrypted_bip85_rsa_entropy(key_bits, index, pubkey, pubkey_len, bip85_data, errmsg)) {
        // errmsg populated
        return CBOR_RPC_INTERNAL_ERROR;
    }

    // Success!
    return 0;
}

int get_bip85_bip39_entropy_cbor(const CborValue* params, CborEncoder* output, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(output);
    JADE_INIT_OUT_PPTR(errmsg);

    // Get bip85
    bip85_data_t bip85_data = { .encrypted_len = 0 };
    const int errcode = get_bip85_bip39_entropy_data(params, &bip85_data, errmsg);
    if (errcode) {
        return errcode;
    }

    // Populate the encrypted bip85 entropy output container
    populate_bip85_reply_data(output, &bip85_data);

    return 0;
}

void get_bip85_bip39_entropy_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_bip85_bip39_entropy");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const char* errmsg = NULL;

    bip85_data_t bip85_data = { .encrypted_len = 0 };
    const int errcode = get_bip85_bip39_entropy_data(&params, &bip85_data, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    // Reply with the encrypted bip85 entropy reply
    jade_process_reply_to_message_result(process->ctx, &bip85_data, reply_bip85_data);
    JADE_LOGI("Success");

cleanup:
    return;
}

void get_bip85_rsa_entropy_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_bip85_rsa_entropy");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    const char* errmsg = NULL;

    bip85_data_t bip85_data = { .encrypted_len = 0 };
    const int errcode = get_bip85_rsa_entropy_data(&params, &bip85_data, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    // Reply with the encrypted bip85 entropy reply
    jade_process_reply_to_message_result(process->ctx, &bip85_data, reply_bip85_data);
    JADE_LOGI("Success");

cleanup:
    return;
}
