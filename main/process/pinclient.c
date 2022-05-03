#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../random.h"
#include "../sensitive.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include <cbor.h>
#include <sodium/crypto_verify_32.h>

#include "process_utils.h"

// Default pinserver url, onion, and public key
static const char PINSERVER_URL[] = "https://jadepin.blockstream.com";
static const char PINSERVER_ONION[] = "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion";
extern const uint8_t server_public_key_start[] asm("_binary_pinserver_public_key_pub_start");

// Pinserver documents to post to
static const char PINSERVER_DOC_INIT[] = "start_handshake";
static const char PINSERVER_DOC_GET_PIN[] = "get_pin";
static const char PINSERVER_DOC_SET_PIN[] = "set_pin";

#define PIN_SECRET_LEN HMAC_SHA256_LEN
#define ENTROPY_LEN HMAC_SHA256_LEN
#define CLIENT_CLEARTEXT_LEN (PIN_SECRET_LEN + ENTROPY_LEN + EC_SIGNATURE_RECOVERABLE_LEN)
#define IV_LEN AES_BLOCK_LEN
#define CLIENT_REQUEST_PAYLOAD_LEN (IV_LEN + ((CLIENT_CLEARTEXT_LEN / AES_BLOCK_LEN + 1) * AES_BLOCK_LEN))
#define SERVER_REPLY_PAYLOAD_LEN (IV_LEN + ((AES_KEY_LEN_256 / AES_BLOCK_LEN + 1) * AES_BLOCK_LEN))

// Helper macro to return pinserver_result_t
#define RETURN_RESULT(rslt, errcode, msg)                                                                              \
    do {                                                                                                               \
        const pinserver_result_t result = { .result = rslt, .errorcode = errcode, .message = msg };                    \
        return result;                                                                                                 \
    } while (false);

// Success or failure, and any error data to send in reply message
typedef struct {
    enum { SUCCESS = 0, CAN_RETRY, FAILURE } result;

    uint32_t errorcode;
    const char* message;
} pinserver_result_t;

typedef struct {
    // The ephemeral server and client ecdh public keys
    uint8_t ske[EC_PUBLIC_KEY_LEN];
    uint8_t cke[EC_PUBLIC_KEY_LEN];

    // The four ephemeral derived keys
    uint8_t encrypt_key[HMAC_SHA256_LEN];
    uint8_t hmac_encrypt_key[HMAC_SHA256_LEN];
    uint8_t decrypt_key[HMAC_SHA256_LEN];
    uint8_t hmac_decrypt_key[HMAC_SHA256_LEN];
} pin_keys_t;

typedef struct {
    const uint8_t* ske;
    const uint8_t* cke;
    const uint8_t* encrypted_data;
    const uint8_t* hmac_encrypted_data;
} handshake_data_t;

typedef struct {
    const char* document;
    const char* on_reply;
    const handshake_data_t* data;
} handshake_reply_t;

// Helper to encode bytes as hex and add as a string to the message
static void add_hex_bytes_to_map(CborEncoder* container, const char* name, const uint8_t* bytes, const size_t size)
{
    JADE_ASSERT(container);
    JADE_ASSERT(name);
    JADE_ASSERT(bytes);

    char* tmpstr;
    JADE_WALLY_VERIFY(wally_hex_from_bytes(bytes, size, &tmpstr));
    add_string_to_map(container, name, tmpstr);
    wally_free_string(tmpstr);
}

// The urls may be overridden in storage, otherwise use the default
static void add_urls(CborEncoder* encoder, const char* document)
{
    char buf[MAX_PINSVR_URL_LENGTH];
    char urlA[sizeof(buf) + sizeof(PINSERVER_DOC_INIT)];
    char urlB[sizeof(buf) + sizeof(PINSERVER_DOC_INIT)];

    // Get first URL (defaults to h/coded url)
    size_t urlA_len = 0;
    const bool urlASet = storage_get_pinserver_urlA(buf, sizeof(buf), &urlA_len);
    if (urlASet && urlA_len <= 1) {
        // Explcitly no url
        urlA[0] = '\0';
    } else {
        urlA_len = snprintf(urlA, sizeof(urlA), "%s/%s", urlASet ? buf : PINSERVER_URL, document);
        JADE_ASSERT(urlA_len > 0 && urlA_len < sizeof(urlA));
    }

    // Get second URL (defaults to h/coded onion)
    size_t urlB_len = 0;
    const bool urlBSet = storage_get_pinserver_urlB(buf, sizeof(buf), &urlB_len);
    if (urlBSet && urlB_len <= 1) {
        // Explcitly no second url
        urlB[0] = '\0';
    } else {
        urlB_len = snprintf(urlB, sizeof(urlB), "%s/%s", urlBSet ? buf : PINSERVER_ONION, document);
        JADE_ASSERT(urlB_len > 0 && urlB_len < sizeof(urlB));
    }

    JADE_ASSERT(urlASet == urlBSet);
    const char* urls[2] = { urlA, urlB };
    add_string_array_to_map(encoder, "urls", urls, 2);
}

// {
//   "http_request": {
//     // params can be passed directly to gdk.http_request()
//     "params": {
//       "urls": [],
//       "root_certificates": [`certificate`]'  ** only present if user has set an additional certificate
//       "method": "POST",
//       "accept": "json",
//       "data": `data`
//     }
//     "on-reply": `on_reply`  ** the result of gdk.http_request(params) should be passed to this method
//   }
static void http_post_cbor(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);

    size_t cert_len = 0;
    char user_certificate[MAX_PINSVR_CERTIFICATE_LENGTH];
    const bool have_certificate = storage_get_pinserver_cert(user_certificate, sizeof(user_certificate), &cert_len);

    const handshake_reply_t* envelope_data = (const handshake_reply_t*)ctx;
    JADE_ASSERT(envelope_data->document);
    JADE_ASSERT(envelope_data->on_reply);

    CborEncoder root_map;
    CborError cberr = cbor_encoder_create_map(container, &root_map, 1);
    JADE_ASSERT(cberr == CborNoError);

    // Envelope data for http request
    cberr = cbor_encode_text_stringz(&root_map, "http_request");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder http_encoder;
    cberr = cbor_encoder_create_map(&root_map, &http_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encode_text_stringz(&http_encoder, "params");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder params_encoder;
    const size_t num_params = have_certificate ? 5 : 4;
    cberr = cbor_encoder_create_map(&http_encoder, &params_encoder, num_params);
    JADE_ASSERT(cberr == CborNoError);

    // The urls (tls and onion) and any associated root certificate we may require
    // These may be the built-in defaults, or may have been overridden (in storage)
    add_urls(&params_encoder, envelope_data->document);

    if (have_certificate) {
        const char* root_certificates[] = { user_certificate };
        add_string_array_to_map(&params_encoder, "root_certificates", root_certificates, 1);
    }

    // The method here is always POST and the payload always json
    add_string_to_map(&params_encoder, "method", "POST");
    add_string_to_map(&params_encoder, "accept", "json");

    // If we have payload data, add that
    const handshake_data_t* payload_data = envelope_data->data;
    if (payload_data) {
        JADE_ASSERT(payload_data->ske);
        JADE_ASSERT(payload_data->cke);
        JADE_ASSERT(payload_data->encrypted_data);
        JADE_ASSERT(payload_data->hmac_encrypted_data);

        cberr = cbor_encode_text_stringz(&params_encoder, "data");
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder data_encoder;
        cberr = cbor_encoder_create_map(&params_encoder, &data_encoder, 4);
        JADE_ASSERT(cberr == CborNoError);

        // Handshake payload data
        add_hex_bytes_to_map(&data_encoder, "ske", payload_data->ske, EC_PUBLIC_KEY_LEN);
        add_hex_bytes_to_map(&data_encoder, "cke", payload_data->cke, EC_PUBLIC_KEY_LEN);
        add_hex_bytes_to_map(&data_encoder, "encrypted_data", payload_data->encrypted_data, CLIENT_REQUEST_PAYLOAD_LEN);
        add_hex_bytes_to_map(&data_encoder, "hmac_encrypted_data", payload_data->hmac_encrypted_data, HMAC_SHA256_LEN);

        cberr = cbor_encoder_close_container(&params_encoder, &data_encoder);
        JADE_ASSERT(cberr == CborNoError);
    } else {
        // Empty placeholder
        add_string_to_map(&params_encoder, "data", "");
    }

    cberr = cbor_encoder_close_container(&http_encoder, &params_encoder);
    JADE_ASSERT(cberr == CborNoError);

    // Add function to call with server's reply payload
    add_string_to_map(&http_encoder, "on-reply", envelope_data->on_reply);

    cberr = cbor_encoder_close_container(&root_map, &http_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(container, &root_map);
    JADE_ASSERT(cberr == CborNoError);
}

// Hepler to verify the server ske is correctly signed - ie. that the server is valid
static bool verify_server_signature(const uint8_t* ske, const size_t ske_len, const uint8_t* sig, const size_t sig_len)
{
    JADE_ASSERT(ske);
    JADE_ASSERT(sig);
    JADE_ASSERT(ske_len == EC_PUBLIC_KEY_LEN);
    JADE_ASSERT(sig_len == EC_SIGNATURE_LEN);

    // The pinserver pubkey - can be default or overridden by user
    const uint8_t* pubkey = server_public_key_start;
    uint8_t user_pubkey[EC_PUBLIC_KEY_LEN];
    if (storage_get_pinserver_pubkey(user_pubkey, sizeof(user_pubkey))) {
        pubkey = user_pubkey;
    }

    int res = wally_ec_public_key_verify(pubkey, EC_PUBLIC_KEY_LEN);
    if (res != WALLY_OK) {
        JADE_LOGE("Invalid pinserver pubkey!");
        return false;
    }

    uint8_t skehash[SHA256_LEN];
    res = wally_sha256(ske, ske_len, skehash, sizeof(skehash));
    if (res != WALLY_OK) {
        JADE_LOGE("Failed to hash pubkey!");
        return false;
    }

    res = wally_ec_sig_verify(pubkey, EC_PUBLIC_KEY_LEN, skehash, sizeof(skehash), EC_FLAG_ECDSA, sig, sig_len);
    return res == WALLY_OK;
}

// Helper to derive a pin-key entry from the shared secret and an index.
// NOTE: the shared-secret must be of size SHA256_LEN, and the output key of size HMAC_SHA256_LEN
static bool derive_secret(const uint8_t* shared_secret, const size_t index, uint8_t* result_key)
{
    uint8_t flags[1] = { index };
    return wally_hmac_sha256(shared_secret, SHA256_LEN, &flags[0], 1, result_key, HMAC_SHA256_LEN) == WALLY_OK;
}

// Hepler function to populate the pinkeys structure given the server key
static bool generate_ecdh_pinkeys(const uint8_t* ske, const size_t ske_len, pin_keys_t* pinkeys)
{
    JADE_ASSERT(ske);
    JADE_ASSERT(ske_len == sizeof(pinkeys->ske));
    JADE_ASSERT(pinkeys);

    bool ret = false;

    uint8_t e_ecdh_privatekey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(e_ecdh_privatekey, sizeof(e_ecdh_privatekey));

    uint8_t shared_secret[SHA256_LEN];
    SENSITIVE_PUSH(shared_secret, sizeof(shared_secret));

    // Copy the ske into pinkeys->ske
    memcpy(pinkeys->ske, ske, ske_len);

    // Get a new ephemeral client key into pinkeys->cke
    if (!keychain_get_new_privatekey(e_ecdh_privatekey, sizeof(e_ecdh_privatekey))) {
        goto cleanup;
    }
    if (wally_ec_public_key_from_private_key(
            e_ecdh_privatekey, sizeof(e_ecdh_privatekey), pinkeys->cke, sizeof(pinkeys->cke))
        != WALLY_OK) {
        goto cleanup;
    }

    // Make the new ecdh 'shared secret' from ske + cke
    if (wally_ecdh(ske, ske_len, e_ecdh_privatekey, sizeof(e_ecdh_privatekey), shared_secret, SHA256_LEN) != WALLY_OK) {
        goto cleanup;
    }

    // Derive the 'pinkeys' from that
    ret = derive_secret(shared_secret, 0, pinkeys->encrypt_key)
        && derive_secret(shared_secret, 1, pinkeys->hmac_encrypt_key)
        && derive_secret(shared_secret, 2, pinkeys->decrypt_key)
        && derive_secret(shared_secret, 3, pinkeys->hmac_decrypt_key);

cleanup:
    SENSITIVE_POP(shared_secret);
    SENSITIVE_POP(e_ecdh_privatekey);
    return ret;
}

// Helper to build the aes-encrypted payload
// Assumes all the passed buffers are non-null and are of the appropriate sizes
static bool encrypt_payload(const uint8_t* aeskey, const uint8_t* pin_secret, const uint8_t* entropy,
    const uint8_t* sig, uint8_t* encrypted, const size_t encrypted_len)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(pin_secret);
    JADE_ASSERT(entropy);
    JADE_ASSERT(sig);
    JADE_ASSERT(encrypted);
    JADE_ASSERT(encrypted_len == CLIENT_REQUEST_PAYLOAD_LEN);

    uint8_t buf[CLIENT_CLEARTEXT_LEN];
    SENSITIVE_PUSH(buf, sizeof(buf));

    memcpy(buf, pin_secret, PIN_SECRET_LEN);
    memcpy(&buf[PIN_SECRET_LEN], entropy, ENTROPY_LEN);
    memcpy(&buf[PIN_SECRET_LEN + ENTROPY_LEN], sig, EC_SIGNATURE_RECOVERABLE_LEN);

    uint8_t iv[IV_LEN];
    get_random(iv, IV_LEN);
    size_t written = 0;
    const int res = wally_aes_cbc(aeskey, AES_KEY_LEN_256, iv, IV_LEN, buf, CLIENT_CLEARTEXT_LEN, AES_FLAG_ENCRYPT,
        &encrypted[IV_LEN], CLIENT_REQUEST_PAYLOAD_LEN - IV_LEN, &written);
    SENSITIVE_POP(buf);

    if (res != WALLY_OK) {
        return false;
    }

    memcpy(encrypted, iv, IV_LEN);
    return true;
}

// Helper to decrypt the aes-encrypted reply - which should be an aes-key (with hmac).
// Assumes all the passed buffers are non-null and are of the appropriate sizes
static bool decrypt_reply(const uint8_t* aeskey, const uint8_t* encrypted, const size_t encrypted_len,
    const uint8_t* hmac, const uint8_t* hmac_key, uint8_t* decryptedaes, const size_t decryptedaes_len)
{
    JADE_ASSERT(aeskey);
    JADE_ASSERT(encrypted);
    JADE_ASSERT(encrypted_len == SERVER_REPLY_PAYLOAD_LEN);
    JADE_ASSERT(hmac);
    JADE_ASSERT(hmac_key);
    JADE_ASSERT(decryptedaes);
    JADE_ASSERT(decryptedaes_len == AES_KEY_LEN_256);

    uint8_t hmac_calculated[HMAC_SHA256_LEN];
    int res = wally_hmac_sha256(hmac_key, HMAC_SHA256_LEN, encrypted, encrypted_len, hmac_calculated, HMAC_SHA256_LEN);
    if (res != WALLY_OK) {
        return false;
    }

    if (crypto_verify_32(hmac_calculated, hmac) != 0) {
        return false;
    }

    size_t written = 0;
    res = wally_aes_cbc(aeskey, AES_KEY_LEN_256, encrypted, IV_LEN, &encrypted[IV_LEN], encrypted_len - IV_LEN,
        AES_FLAG_DECRYPT, decryptedaes, decryptedaes_len, &written);
    return res == WALLY_OK && written == AES_KEY_LEN_256;
}

// Trigger, and then parse, handshake_init message
// Sets-up the ECDH and the ephemeral encryption keys - populates pinkeys structure
// Returns a small struct containing the success/fail, whether it is a 'hard' or
// 'retryable' error, and any error code/message that should be sent.
static pinserver_result_t start_handshake(jade_process_t* process, pin_keys_t* pinkeys)
{
    JADE_ASSERT(process);
    JADE_ASSERT(pinkeys);
    ASSERT_HAS_CURRENT_MESSAGE(process);

    CborValue params;
    uint8_t ske[EC_PUBLIC_KEY_LEN];
    uint8_t sig[EC_SIGNATURE_LEN];
    char tmpstr[256];

    // Send a reply with the handshake url
    JADE_LOGD("Initiating server handshake with: %s", PINSERVER_URL);
    const handshake_reply_t handshake_init
        = { .document = PINSERVER_DOC_INIT, .on_reply = "handshake_init", .data = NULL };
    jade_process_reply_to_message_result(process->ctx, &handshake_init, http_post_cbor);

    // Await a 'handshake_init' message
    jade_process_load_in_message(process, true);

    if (!IS_CURRENT_MESSAGE(process, "handshake_init")) {
        // Protocol error
        RETURN_RESULT(FAILURE, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'handshake_init'");
    }

    // If we receive no parameters it implies some comms failure with the pinserver
    // This is an error we can retry and is not a 'wrong pin' type failure.
    const CborError cberr = cbor_value_map_find_value(&process->ctx.value, CBOR_RPC_TAG_PARAMS, &params);
    if (cberr != CborNoError || !cbor_value_is_valid(&params) || cbor_value_get_type(&params) == CborInvalidType
        || !cbor_value_is_map(&params)) {
        // We provide the error details in case the user opts not to retry
        RETURN_RESULT(CAN_RETRY, CBOR_RPC_BAD_PARAMETERS, "Failed to read parameters from pinserver");
    }

    // ske
    size_t len = 0;
    rpc_get_string("ske", sizeof(tmpstr), &params, tmpstr, &len);
    if (len == 0) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "ske missing");
    }

    len = 0;
    if (wally_hex_to_bytes(tmpstr, ske, sizeof(ske), &len) != WALLY_OK || len != EC_PUBLIC_KEY_LEN) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "ske invalid");
    }

    // sig
    len = 0;
    rpc_get_string("sig", sizeof(tmpstr), &params, tmpstr, &len);
    if (len == 0) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "sig missing");
    }

    len = 0;
    if (wally_hex_to_bytes(tmpstr, sig, sizeof(sig), &len) != WALLY_OK || len != EC_SIGNATURE_LEN) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "sig invalid");
    }

    // Verify server key/signature
    if (!verify_server_signature(ske, sizeof(ske), sig, sizeof(sig))) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "Cannot initiate handshake - ske and/or sig invalid");
    }

    // Derive all the various encryption keys
    JADE_LOGD("Deriving shared secrets/keys");
    if (!generate_ecdh_pinkeys(ske, sizeof(ske), pinkeys)) {
        RETURN_RESULT(
            FAILURE, CBOR_RPC_INTERNAL_ERROR, "Cannot initiate handshake - failed to generate shared secrets");
    }

    // Success!
    RETURN_RESULT(SUCCESS, 0, NULL);
}

// Trigger, and then parse, handshake_complete message
// Use the ephemeral encryption keys to decrypt the main payload (server aes key)
// Returns a small struct containing the success/fail, whether it is a 'hard' or
// 'retryable' error, and any error code/message that should be sent.
static pinserver_result_t complete_handshake(
    jade_process_t* process, const pin_keys_t* pinkeys, uint8_t* serverkey, const size_t serverkey_len)
{
    JADE_ASSERT(process);
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(serverkey);
    JADE_ASSERT(serverkey_len == AES_KEY_LEN_256);
    ASSERT_CURRENT_MESSAGE(process, "handshake_init");

    CborValue params;
    uint8_t aes_encrypted[SERVER_REPLY_PAYLOAD_LEN];
    uint8_t aes_hmac[HMAC_SHA256_LEN];
    char tmpstr[256];

    // Await a 'complete_handshake' message
    jade_process_load_in_message(process, true);

    if (!IS_CURRENT_MESSAGE(process, "handshake_complete")) {
        // Protocol error
        RETURN_RESULT(FAILURE, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'handshake_complete'");
    }

    // If we receive no parameters it implies some comms failure with the pinserver
    // This is an error we can retry and is not a 'wrong pin' type failure.
    const CborError cberr = cbor_value_map_find_value(&process->ctx.value, CBOR_RPC_TAG_PARAMS, &params);
    if (cberr != CborNoError || !cbor_value_is_valid(&params) || cbor_value_get_type(&params) == CborInvalidType
        || !cbor_value_is_map(&params)) {
        // We provide the error details in case the user opts not to retry
        RETURN_RESULT(CAN_RETRY, CBOR_RPC_BAD_PARAMETERS, "Failed to read parameters from pinserver");
    }

    // encrypted key
    size_t len = 0;
    rpc_get_string("encrypted_key", sizeof(tmpstr), &params, tmpstr, &len);
    if (len == 0) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "encrypted_key missing");
    }

    len = 0;
    if (wally_hex_to_bytes(tmpstr, aes_encrypted, sizeof(aes_encrypted), &len) != WALLY_OK
        || len != SERVER_REPLY_PAYLOAD_LEN) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "encrypted_key invalid");
    }

    // hmac
    len = 0;
    rpc_get_string("hmac", sizeof(tmpstr), &params, tmpstr, &len);
    if (len == 0) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "hmac missing");
    }

    len = 0;
    if (wally_hex_to_bytes(tmpstr, aes_hmac, sizeof(aes_hmac), &len) != WALLY_OK || len != HMAC_SHA256_LEN) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "hmac invalid");
    }

    // Decrypt the message payload and check hmacs
    JADE_LOGD("Decrypting response and obtaining server key");
    if (!decrypt_reply(pinkeys->decrypt_key, aes_encrypted, sizeof(aes_encrypted), aes_hmac, pinkeys->hmac_decrypt_key,
            serverkey, serverkey_len)) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "failed to decrypt payload");
    }

    // Success!
    RETURN_RESULT(SUCCESS, 0, NULL);
}

// Helper to hmac an n-digit pin into a 256bit secret
static bool get_pin_secret(const uint8_t* pin, const size_t pin_len, const uint8_t* pin_privatekey, uint8_t* pin_secret)
{
    JADE_ASSERT(pin);
    JADE_ASSERT(pin_len > 0);
    JADE_ASSERT(pin_privatekey);
    JADE_ASSERT(pin_secret);

    const uint8_t subkey = 0;
    uint8_t hmac_key[HMAC_SHA256_LEN];
    SENSITIVE_PUSH(hmac_key, sizeof(hmac_key));

    const bool ret
        = wally_hmac_sha256(pin_privatekey, EC_PRIVATE_KEY_LEN, &subkey, 1, hmac_key, HMAC_SHA256_LEN) == WALLY_OK
        && wally_hmac_sha256(hmac_key, sizeof(hmac_key), pin, pin_len, pin_secret, HMAC_SHA256_LEN) == WALLY_OK;

    SENSITIVE_POP(hmac_key);
    return ret;
}

// Sign the payload with the private key
static bool sign_payload(
    const uint8_t* pin_privatekey, const uint8_t* cke, const uint8_t* pinsecret, const uint8_t* entropy, uint8_t* sig)
{
    JADE_ASSERT(pin_privatekey);
    JADE_ASSERT(cke);
    JADE_ASSERT(pinsecret);
    JADE_ASSERT(entropy);
    JADE_ASSERT(sig);

    uint8_t shahash[SHA256_LEN];
    SENSITIVE_PUSH(shahash, sizeof(shahash));
    uint8_t shadata[EC_PUBLIC_KEY_LEN + PIN_SECRET_LEN + ENTROPY_LEN];
    SENSITIVE_PUSH(shadata, sizeof(shadata));

    memcpy(shadata, cke, EC_PUBLIC_KEY_LEN);
    memcpy(&shadata[EC_PUBLIC_KEY_LEN], pinsecret, PIN_SECRET_LEN);
    memcpy(&shadata[EC_PUBLIC_KEY_LEN + PIN_SECRET_LEN], entropy, ENTROPY_LEN);

    const bool ret = wally_sha256(shadata, sizeof(shadata), shahash, sizeof(shahash)) == WALLY_OK
        && wally_ec_sig_from_bytes(pin_privatekey, EC_PRIVATE_KEY_LEN, shahash, sizeof(shahash),
               EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE, sig, EC_SIGNATURE_RECOVERABLE_LEN)
            == WALLY_OK;

    SENSITIVE_POP(shadata);
    SENSITIVE_POP(shahash);
    return ret;
}

// Calculate the hmac of the cke + (encrypted) payload
static bool hmac_ckepayload(const pin_keys_t* pinkeys, const uint8_t* payload, uint8_t* output)
{
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(payload);
    JADE_ASSERT(output);

    uint8_t data[EC_PUBLIC_KEY_LEN + CLIENT_REQUEST_PAYLOAD_LEN];
    memcpy(data, pinkeys->cke, EC_PUBLIC_KEY_LEN);
    memcpy(&data[EC_PUBLIC_KEY_LEN], payload, CLIENT_REQUEST_PAYLOAD_LEN);

    return wally_hmac_sha256(pinkeys->hmac_encrypt_key, sizeof(pinkeys->hmac_encrypt_key), data, sizeof(data), output,
               HMAC_SHA256_LEN)
        == WALLY_OK;
}

// Dance with the pinserver to obtain the final aes-key - start handshake,
// compute shared secrets, fetch server key, and then compute final aes key.
static pinserver_result_t pinserver_interaction(jade_process_t* process, const uint8_t* pin, const size_t pin_len,
    const char* document, uint8_t* finalaes, const size_t finalaes_len)
{
    JADE_ASSERT(process);
    JADE_ASSERT(pin);
    JADE_ASSERT(pin_len > 0);
    JADE_ASSERT(document);
    JADE_ASSERT(finalaes);
    JADE_ASSERT(finalaes_len == AES_KEY_LEN_256);
    ASSERT_HAS_CURRENT_MESSAGE(process);

    pin_keys_t pinkeys;
    uint8_t pin_privatekey[EC_PRIVATE_KEY_LEN];
    uint8_t pinsecret[PIN_SECRET_LEN];
    uint8_t entropy[ENTROPY_LEN];
    uint8_t sig[EC_SIGNATURE_RECOVERABLE_LEN];
    uint8_t payload[CLIENT_REQUEST_PAYLOAD_LEN];
    uint8_t hmac_payload[HMAC_SHA256_LEN];

    SENSITIVE_PUSH(&pinkeys, sizeof(pinkeys));
    SENSITIVE_PUSH(pin_privatekey, sizeof(pin_privatekey));
    SENSITIVE_PUSH(pinsecret, sizeof(pinsecret));
    SENSITIVE_PUSH(entropy, sizeof(entropy));
    SENSITIVE_PUSH(sig, sizeof(sig));

    // Start the pinserver handshake and derive the shared encryption keys
    pinserver_result_t retval = start_handshake(process, &pinkeys);
    if (retval.result != SUCCESS) {
        goto cleanup;
    }

    // Generate, sign, encrypt and hmac the pin data to send
    JADE_LOGI("Generating pinserver payload");
    get_random(entropy, sizeof(entropy));

    if (!storage_get_pin_privatekey(pin_privatekey, sizeof(pin_privatekey))
        || !get_pin_secret(pin, pin_len, pin_privatekey, pinsecret)
        || !sign_payload(pin_privatekey, pinkeys.cke, pinsecret, entropy, sig)
        || !encrypt_payload(pinkeys.encrypt_key, pinsecret, entropy, sig, payload, sizeof(payload))
        || !hmac_ckepayload(&pinkeys, payload, hmac_payload)) {
        // Internal failure
        retval.result = FAILURE;
        retval.errorcode = CBOR_RPC_INTERNAL_ERROR;
        retval.message = "Failed to create pinserver message content";
        goto cleanup;
    }

    // Build and send cbor reply
    const handshake_data_t payload_data
        = { .ske = pinkeys.ske, .cke = pinkeys.cke, .encrypted_data = payload, .hmac_encrypted_data = hmac_payload };
    const handshake_reply_t handshake_complete
        = { .document = document, .on_reply = "handshake_complete", .data = &payload_data };
    jade_process_reply_to_message_result(process->ctx, &handshake_complete, http_post_cbor);

    // Get the server's aes key for the given pin/key data
    uint8_t serverkey[AES_KEY_LEN_256];
    retval = complete_handshake(process, &pinkeys, serverkey, sizeof(serverkey));
    if (retval.result != SUCCESS) {
        goto cleanup;
    }

    // Derive the final aes key by combining the server key with the pin
    JADE_LOGI("Deriving final aes-key");
    JADE_WALLY_VERIFY(wally_hmac_sha256(serverkey, sizeof(serverkey), pin, pin_len, finalaes, finalaes_len));

    // Success - well nothing has obviously failed anyway
    JADE_ASSERT(retval.result == SUCCESS);

cleanup:
    SENSITIVE_POP(sig);
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(pinsecret);
    SENSITIVE_POP(pin_privatekey);
    SENSITIVE_POP(&pinkeys);

    return retval;
}

// Dance with the pinserver to obtain the final aes-key.  Wraps pinserver interaction
// with retry logic in-case there are http/network issues.
static bool get_pinserver_aeskey(jade_process_t* process, const uint8_t* pin, const size_t pin_len,
    const char* document, uint8_t* finalaes, const size_t finalaes_len)
{
    // pinserver interaction only happens atm as a result of a call to 'auth_user'
    ASSERT_CURRENT_MESSAGE(process, "auth_user");

    while (true) {
        // Do the pinserver interaction dance, and get the resulting aes-key
        const pinserver_result_t pir = pinserver_interaction(process, pin, pin_len, document, finalaes, finalaes_len);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        // If a) the error is 'retry-able' and b) the user elects to retry, then loop and try again
        // (In a CI build no GUI, so assume 'no' and return the error immediately.)
        if (pir.result == CAN_RETRY
            && await_yesno_activity("Network Error", "\nFailed communicating with\npin-server - retry ?", true)) {
            display_message_activity("Retrying ...");
            continue;
        }
#endif
        if (pir.result != SUCCESS) {
            // If failed, send reject message
            JADE_LOGE("Failed to complete pinserver interaction");
            jade_process_reject_message(process, pir.errorcode, pir.message, NULL);
            await_error_activity("Network or server error");
            return false;
        }

        // Otherwise all good, return true
        return true;
    }
}

// Interact with the pinserver to get the server's key
// Then return the final aes key.
bool pinclient_get(
    jade_process_t* process, const uint8_t* pin, const size_t pin_len, uint8_t* finalaes, const size_t finalaes_len)
{
    JADE_LOGI("Fetching pinserver data");
    return get_pinserver_aeskey(process, pin, pin_len, PINSERVER_DOC_GET_PIN, finalaes, finalaes_len);
}

// Interact with the pinserver to get a new server key
// Then return the (new) final aes key.
bool pinclient_set(
    jade_process_t* process, const uint8_t* pin, const size_t pin_len, uint8_t* finalaes, const size_t finalaes_len)
{
    // Dance with the pin-server 'set_pin' address
    JADE_LOGI("Setting new pinserver data");
    return get_pinserver_aeskey(process, pin, pin_len, PINSERVER_DOC_SET_PIN, finalaes, finalaes_len);
}
