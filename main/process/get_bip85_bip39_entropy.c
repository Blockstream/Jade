#include "../aes.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../process.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../wallet.h"

#include "process_utils.h"

typedef struct {
    uint8_t encrypted[AES_ENCRYPTED_LEN(HMAC_SHA512_LEN)];
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    uint8_t hmac[HMAC_SHA256_LEN];
    size_t encrypted_len;
} bip85_data_t;

void await_qr_help_activity(const char* url);

static void populate_bip85_reply_data(CborEncoder* container, const bip85_data_t* bip85_data)
{
    JADE_ASSERT(container);
    JADE_ASSERT(bip85_data);
    JADE_ASSERT(bip85_data->encrypted_len);

    CborEncoder map_encoder; // result data
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "pubkey", bip85_data->pubkey, sizeof(bip85_data->pubkey));
    add_bytes_to_map(&map_encoder, "encrypted", bip85_data->encrypted, bip85_data->encrypted_len);
    add_bytes_to_map(&map_encoder, "hmac", bip85_data->hmac, sizeof(bip85_data->hmac));

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
    uint8_t shared_secret[SHA256_LEN];
    SENSITIVE_PUSH(shared_secret, sizeof(shared_secret));
    uint8_t encryption_key[SHA256_LEN];
    SENSITIVE_PUSH(encryption_key, sizeof(encryption_key));
    uint8_t hmac_key[SHA256_LEN];
    SENSITIVE_PUSH(hmac_key, sizeof(hmac_key));
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

    // Make the new ecdh 'shared secret' with the passed pubkey, and derive two further keys
    const uint8_t derived_key_data[] = { 1, 2 };
    if (wally_ecdh(pubkey, pubkey_len, eph_privkey, sizeof(eph_privkey), shared_secret, sizeof(shared_secret))
            != WALLY_OK
        || wally_hmac_sha256(shared_secret, sizeof(shared_secret), &derived_key_data[0], sizeof(derived_key_data[0]),
               encryption_key, sizeof(encryption_key))
            != WALLY_OK
        || wally_hmac_sha256(shared_secret, sizeof(shared_secret), &derived_key_data[1], sizeof(derived_key_data[1]),
               hmac_key, sizeof(hmac_key))
            != WALLY_OK) {
        *errmsg = "Failed to compute shared ecdh secret and derived keys";
        goto cleanup;
    }

    // Generate the bip85/bip39 entropy
    size_t entropy_len = 0;
    wallet_get_bip85_bip39_entropy(nwords, index, entropy, sizeof(entropy), &entropy_len);
    if (!entropy_len || entropy_len > sizeof(entropy)) {
        *errmsg = "Failed to calculate bip85 entropy from parameters";
        goto cleanup;
    }

    // Encrypt the entropy with the first key derived from the shared secret
    bip85_data->encrypted_len = AES_ENCRYPTED_LEN(entropy_len);
    JADE_ASSERT(bip85_data->encrypted_len <= sizeof(bip85_data->encrypted));
    if (!aes_encrypt_bytes(encryption_key, sizeof(encryption_key), entropy, entropy_len, bip85_data->encrypted,
            bip85_data->encrypted_len)) {
        *errmsg = "Failed to encrypt bip85 entropy";
        goto cleanup;
    }

    // hmac the encrypted data
    if (wally_hmac_sha256(hmac_key, sizeof(hmac_key), bip85_data->encrypted, bip85_data->encrypted_len,
            bip85_data->hmac, sizeof(bip85_data->hmac))
        != WALLY_OK) {
        *errmsg = "Failed to hmac encrypted payload";
        goto cleanup;
    }

    retval = true;
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(hmac_key);
    SENSITIVE_POP(encryption_key);
    SENSITIVE_POP(shared_secret);
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
    char idx[8];
    int ret = snprintf(idx, sizeof(idx), "%u", index);
    JADE_ASSERT(ret > 0 && ret < sizeof(idx));
    const int padding = (sizeof(idx) - ret) / 2;
    char msg[96];
    ret = snprintf(msg, sizeof(msg), "  Export an encrypted\n  %u word seed phrase\n%*sfor BIP85 index %s?", nwords,
        padding, "", idx);
    JADE_ASSERT(ret > 0 && ret < sizeof(msg));

    if (!await_continueback_activity("Key Export", msg, false, "blkstrm.com/bip85")) {
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
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());
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
