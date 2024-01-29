#include "../aes.h"
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
#include <mbedtls/base64.h>
#include <sodium/crypto_verify_32.h>

#include "process_utils.h"

// Default pinserver url, onion, and public key
static const char PINSERVER_URL[] = "https://j8d.io";
static const char PINSERVER_ONION[] = "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion";
extern const uint8_t server_public_key_start[] asm("_binary_pinserver_public_key_pub_start");

// Pinserver documents to post to
static const char PINSERVER_DOC_GET_PIN[] = "get_pin";
static const char PINSERVER_DOC_SET_PIN[] = "set_pin";

// Fixed hmac keys used to derive ephemeral encrpytion keys
static const unsigned char LABEL_ORACLE_REQUEST[]
    = { 'b', 'l', 'i', 'n', 'd', '_', 'o', 'r', 'a', 'c', 'l', 'e', '_', 'r', 'e', 'q', 'u', 'e', 's', 't' };
static const unsigned char LABEL_ORACLE_RESPONSE[]
    = { 'b', 'l', 'i', 'n', 'd', '_', 'o', 'r', 'a', 'c', 'l', 'e', '_', 'r', 'e', 's', 'p', 'o', 'n', 's', 'e' };

#define PIN_SECRET_LEN HMAC_SHA256_LEN
#define ENTROPY_LEN HMAC_SHA256_LEN
#define CLIENT_MAX_CLEARTEXT_LEN (PIN_SECRET_LEN + ENTROPY_LEN + EC_SIGNATURE_RECOVERABLE_LEN)
#define CLIENT_REQUEST_MAX_PAYLOAD_LEN (AES_ENCRYPTED_LEN(CLIENT_MAX_CLEARTEXT_LEN) + HMAC_SHA256_LEN)
#define SERVER_REPLY_PAYLOAD_LEN (AES_ENCRYPTED_LEN(AES_KEY_LEN_256) + HMAC_SHA256_LEN)
#define REPLAY_COUNTER_LEN 4

// Helper macro to return pinserver_result_t
#define RETURN_RESULT(rslt, errcode, msg)                                                                              \
    do {                                                                                                               \
        const pinserver_result_t result = { .result = rslt, .errorcode = errcode, .message = msg };                    \
        return result;                                                                                                 \
    } while (false);

// Success or failure, and any error data to send in reply message
typedef struct {
    enum { SUCCESS = 0, CAN_RETRY, FAILURE, CANCELLED } result;

    uint32_t errorcode;
    const char* message;
} pinserver_result_t;

typedef struct {
    // The tweak derived server ecdh public key
    uint8_t ske[EC_PUBLIC_KEY_LEN];
    // The ephemeral client ecdh keys
    uint8_t cke[EC_PUBLIC_KEY_LEN];
    uint8_t privkey[EC_PRIVATE_KEY_LEN];
    // Monotonic Forward Replay counter required for v2
    uint8_t replay_counter[REPLAY_COUNTER_LEN];
} pin_keys_t;

typedef struct {
    const char* document;
    const char* on_reply;
    const char* data;
} pin_data_t;

// The urls may be overridden in storage, otherwise use the default
static void add_urls(CborEncoder* encoder, const char* document)
{
    char buf[MAX_PINSVR_URL_LENGTH];
    char urlA[sizeof(buf) + sizeof(PINSERVER_DOC_GET_PIN)];
    char urlB[sizeof(buf) + sizeof(PINSERVER_DOC_GET_PIN)];

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
static void http_post_reply(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(container);

    size_t cert_len = 0;
    char user_certificate[MAX_PINSVR_CERTIFICATE_LENGTH];
    const bool have_certificate = storage_get_pinserver_cert(user_certificate, sizeof(user_certificate), &cert_len);

    const pin_data_t* reply_data = (const pin_data_t*)ctx;
    JADE_ASSERT(reply_data->document);
    JADE_ASSERT(reply_data->on_reply);
    JADE_ASSERT(reply_data->data);

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
    add_urls(&params_encoder, reply_data->document);

    if (have_certificate) {
        const char* root_certificates[] = { user_certificate };
        add_string_array_to_map(&params_encoder, "root_certificates", root_certificates, 1);
    }

    // The method here is always POST and the payload always json
    add_string_to_map(&params_encoder, "method", "POST");
    add_string_to_map(&params_encoder, "accept", "json");

    // Add payload data
    cberr = cbor_encode_text_stringz(&params_encoder, "data");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder data_encoder;
    cberr = cbor_encoder_create_map(&params_encoder, &data_encoder, 1);
    JADE_ASSERT(cberr == CborNoError);

    // Payload data - one large opaque base64 string
    add_string_to_map(&data_encoder, "data", reply_data->data);

    cberr = cbor_encoder_close_container(&params_encoder, &data_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(&http_encoder, &params_encoder);
    JADE_ASSERT(cberr == CborNoError);

    // Add function to call with server's reply payload
    add_string_to_map(&http_encoder, "on-reply", reply_data->on_reply);

    cberr = cbor_encoder_close_container(&root_map, &http_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(container, &root_map);
    JADE_ASSERT(cberr == CborNoError);
}

// Hepler to tweak the server static key into a session key
static bool generate_ske(pin_keys_t* pinkeys)
{
    JADE_ASSERT(pinkeys);

    // The pinserver pubkey - can be default or overridden by user
    const uint8_t* pubkey = server_public_key_start;
    uint8_t user_pubkey[EC_PUBLIC_KEY_LEN];
    uint8_t hmac_tweak[HMAC_SHA256_LEN];
    uint8_t sha_tweak[SHA256_LEN];
    if (storage_get_pinserver_pubkey(user_pubkey, sizeof(user_pubkey))) {
        pubkey = user_pubkey;
    }

    if (wally_ec_public_key_verify(pubkey, EC_PUBLIC_KEY_LEN) != WALLY_OK) {
        JADE_LOGE("Invalid pinserver pubkey!");
        return false;
    }

    if (wally_hmac_sha256(
            pinkeys->cke, EC_PUBLIC_KEY_LEN, pinkeys->replay_counter, REPLAY_COUNTER_LEN, hmac_tweak, HMAC_SHA256_LEN)
        != WALLY_OK) {
        return false;
    }

    if (wally_sha256(hmac_tweak, sizeof(hmac_tweak), sha_tweak, sizeof(sha_tweak)) != WALLY_OK) {
        return false;
    }

    if (wally_ec_public_key_bip341_tweak(
            pubkey, EC_PUBLIC_KEY_LEN, sha_tweak, SHA256_LEN, 0, pinkeys->ske, sizeof(pinkeys->ske))
        != WALLY_OK) {
        return false;
    }
    return true;
}

// Helper to build the aes-encrypted payload
// Assumes all the passed buffers are non-null and are of the appropriate sizes
static bool encrypt_payload(const pin_keys_t* pinkeys, const uint8_t* pin_secret, const size_t pin_secret_len,
    const uint8_t* entropy, const size_t entropy_len, const uint8_t* sig, const size_t sig_len, uint8_t* encrypted,
    const size_t encrypted_len, size_t* written)
{
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(pin_secret);
    JADE_ASSERT(pin_secret_len == PIN_SECRET_LEN);
    JADE_ASSERT(entropy || !entropy_len);
    JADE_ASSERT(!entropy_len || entropy_len == ENTROPY_LEN);
    JADE_ASSERT(sig);
    JADE_ASSERT(sig_len == EC_SIGNATURE_RECOVERABLE_LEN);
    JADE_ASSERT(encrypted);
    JADE_ASSERT(encrypted_len == CLIENT_REQUEST_MAX_PAYLOAD_LEN);
    JADE_INIT_OUT_SIZE(written);

    uint8_t cleartext[CLIENT_MAX_CLEARTEXT_LEN];
    SENSITIVE_PUSH(cleartext, sizeof(cleartext));

    const size_t cleartext_len = pin_secret_len + entropy_len + sig_len;
    JADE_ASSERT(cleartext_len <= sizeof(cleartext));

    memcpy(cleartext, pin_secret, pin_secret_len);
    memcpy(&cleartext[pin_secret_len], entropy, entropy_len);
    memcpy(&cleartext[pin_secret_len + entropy_len], sig, sig_len);

    uint8_t iv[AES_BLOCK_LEN];
    get_random(iv, sizeof(iv));
    const int wret = wally_aes_cbc_with_ecdh_key(pinkeys->privkey, sizeof(pinkeys->privkey), iv, sizeof(iv), cleartext,
        cleartext_len, pinkeys->ske, sizeof(pinkeys->ske), LABEL_ORACLE_REQUEST, sizeof(LABEL_ORACLE_REQUEST),
        AES_FLAG_ENCRYPT, encrypted, encrypted_len, written);
    SENSITIVE_POP(cleartext);

    return wret == WALLY_OK && *written <= encrypted_len;
}

// Helper to decrypt the aes-encrypted reply - which should be an aes-key.
// Assumes all the passed buffers are non-null and are of the appropriate sizes
static bool decrypt_reply(const pin_keys_t* pinkeys, const uint8_t* encrypted, const size_t encrypted_len,
    uint8_t* decryptedaes, const size_t decryptedaes_len)
{
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(encrypted);
    JADE_ASSERT(encrypted_len == SERVER_REPLY_PAYLOAD_LEN);
    JADE_ASSERT(decryptedaes);
    JADE_ASSERT(decryptedaes_len == AES_KEY_LEN_256);

    // In theory the decrypted payload can be up to the size of the encrypted payload minus
    // the iv (an aes block len), *after* we've removed the trailing hmac.  It can be smaller - in
    // fact in this case we are expecting to decrypt exactly 32 bytes (aes key len)
    uint8_t decrypted_padded[SERVER_REPLY_PAYLOAD_LEN - HMAC_SHA256_LEN - AES_BLOCK_LEN];
    size_t written = 0;
    if (wally_aes_cbc_with_ecdh_key(pinkeys->privkey, sizeof(pinkeys->privkey), NULL, 0, encrypted, encrypted_len,
            pinkeys->ske, sizeof(pinkeys->ske), LABEL_ORACLE_RESPONSE, sizeof(LABEL_ORACLE_RESPONSE), AES_FLAG_DECRYPT,
            decrypted_padded, sizeof(decrypted_padded), &written)
            != WALLY_OK
        || written != decryptedaes_len) {
        return false;
    }
    memcpy(decryptedaes, decrypted_padded, written);
    return true;
}

// Generate a random client-side ephemeral key, and derive the server key via tweak.
// Populates passed pinkeys structure.
// Returns a small struct containing the success/fail, and any error
// code/message that should be sent.
static pinserver_result_t generate_ephemeral_pinkeys(pin_keys_t* pinkeys)
{
    JADE_ASSERT(pinkeys);

    // Get a new ephemeral client key into pinkeys
    if (!keychain_get_new_privatekey(pinkeys->privkey, sizeof(pinkeys->privkey))
        || wally_ec_public_key_from_private_key(
               pinkeys->privkey, sizeof(pinkeys->privkey), pinkeys->cke, sizeof(pinkeys->cke))
            != WALLY_OK) {
        JADE_LOGE("Failed to generate ephemeral client key");
        RETURN_RESULT(
            FAILURE, CBOR_RPC_INTERNAL_ERROR, "Cannot initiate handshake - failed to generate ephemeral client key");
    }

    // Load the replay counter and deduce the server key via tweak
    const bool res = storage_get_replay_counter(pinkeys->replay_counter);
    if (!res || !generate_ske(pinkeys)) {
        JADE_LOGE("Failed to deduce ephemeral server key");
        RETURN_RESULT(
            FAILURE, CBOR_RPC_INTERNAL_ERROR, "Cannot initiate handshake - failed to deduce ephemeral server key");
    }

    // Success!
    RETURN_RESULT(SUCCESS, 0, NULL);
}

// Trigger, and then parse, 'pin' message
// Use the ephemeral encryption keys to decrypt the main payload (server aes key)
// Returns a small struct containing the success/fail, whether it is a 'hard' or
// 'retryable' error, and any error code/message that should be sent.
static pinserver_result_t handle_pin(
    jade_process_t* process, const pin_keys_t* pinkeys, uint8_t* serverkey, const size_t serverkey_len)
{
    JADE_ASSERT(process);
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(serverkey);
    JADE_ASSERT(serverkey_len == AES_KEY_LEN_256);

    ASSERT_CURRENT_MESSAGE(process, "auth_user");

    CborValue params;
    uint8_t aes_encrypted[512]; // sufficient for correct payload

    // Await a 'pin' message
    jade_process_load_in_message(process, true);

    if (IS_CURRENT_MESSAGE(process, "cancel")) {
        // Cancelled
        RETURN_RESULT(CANCELLED, 0, NULL);
    } else if (!IS_CURRENT_MESSAGE(process, "pin")) {
        // Protocol error
        RETURN_RESULT(FAILURE, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'pin'");
    }

    // If we receive no parameters it implies some comms failure with the pinserver
    // This is an error we can retry and is not a 'wrong pin' type failure.
    const CborError cberr = cbor_value_map_find_value(&process->ctx.value, CBOR_RPC_TAG_PARAMS, &params);
    if (cberr != CborNoError || !cbor_value_is_valid(&params) || cbor_value_get_type(&params) == CborInvalidType
        || !cbor_value_is_map(&params)) {
        // We provide the error details in case the user opts not to retry
        RETURN_RESULT(CAN_RETRY, CBOR_RPC_BAD_PARAMETERS, "Failed to read parameters from Oracle");
    }

    // encrypted key
    size_t data_len = 0;
    const char* data = NULL;
    rpc_get_string_ptr("data", &params, &data, &data_len);
    if (!data || !data_len) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "data field missing");
    }

    size_t written = 0;
    if (mbedtls_base64_decode(aes_encrypted, sizeof(aes_encrypted), &written, (const uint8_t*)data, data_len)
        || written != SERVER_REPLY_PAYLOAD_LEN) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "data field invalid");
    }

    // Decrypt the message payload and check hmacs
    JADE_LOGD("Decrypting response and obtaining server key");
    if (!decrypt_reply(pinkeys, aes_encrypted, written, serverkey, serverkey_len)) {
        RETURN_RESULT(FAILURE, CBOR_RPC_BAD_PARAMETERS, "Failed to decrypt payload");
    }

    // Success!
    RETURN_RESULT(SUCCESS, 0, NULL);
}

// Helper to hmac an n-digit pin into a 256bit secret
static bool get_pin_secret(const uint8_t* pin, const size_t pin_len, const uint8_t* pin_privatekey,
    const size_t pin_privatekey_len, uint8_t* pin_secret, const size_t pin_secret_len)
{
    JADE_ASSERT(pin);
    JADE_ASSERT(pin_len > 0);
    JADE_ASSERT(pin_privatekey);
    JADE_ASSERT(pin_privatekey_len == EC_PRIVATE_KEY_LEN);
    JADE_ASSERT(pin_secret);
    JADE_ASSERT(pin_secret_len == PIN_SECRET_LEN);

    const uint8_t subkey = 0;
    uint8_t hmac_key[HMAC_SHA256_LEN];
    SENSITIVE_PUSH(hmac_key, sizeof(hmac_key));

    const bool ret
        = wally_hmac_sha256(pin_privatekey, pin_privatekey_len, &subkey, 1, hmac_key, sizeof(hmac_key)) == WALLY_OK
        && wally_hmac_sha256(hmac_key, sizeof(hmac_key), pin, pin_len, pin_secret, pin_secret_len) == WALLY_OK;

    SENSITIVE_POP(hmac_key);
    return ret;
}

// Sign the payload with the private key
static bool sign_payload(const uint8_t* pin_privatekey, const size_t pin_privatekey_len, const pin_keys_t* pinkeys,
    const uint8_t* pinsecret, const size_t pinsecret_len, const uint8_t* entropy, const size_t entropy_len,
    uint8_t* sig, const size_t sig_len)
{
    JADE_ASSERT(pin_privatekey);
    JADE_ASSERT(pin_privatekey_len == EC_PRIVATE_KEY_LEN);
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(pinsecret);
    JADE_ASSERT(pinsecret_len == PIN_SECRET_LEN);
    JADE_ASSERT(entropy || !entropy_len);
    JADE_ASSERT(!entropy_len || entropy_len == ENTROPY_LEN);
    JADE_ASSERT(sig);
    JADE_ASSERT(sig_len == EC_SIGNATURE_RECOVERABLE_LEN);

    uint8_t shahash[SHA256_LEN];
    SENSITIVE_PUSH(shahash, sizeof(shahash));
    uint8_t shadata[sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter) + PIN_SECRET_LEN + ENTROPY_LEN];
    SENSITIVE_PUSH(shadata, sizeof(shadata));

    const size_t shadata_len = sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter) + pinsecret_len + entropy_len;
    JADE_ASSERT(shadata_len <= sizeof(shadata));

    memcpy(shadata, pinkeys->cke, sizeof(pinkeys->cke));
    memcpy(&shadata[sizeof(pinkeys->cke)], pinkeys->replay_counter, sizeof(pinkeys->replay_counter));
    memcpy(&shadata[sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter)], pinsecret, pinsecret_len);
    memcpy(&shadata[sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter) + pinsecret_len], entropy, entropy_len);

    const bool ret = wally_sha256(shadata, shadata_len, shahash, sizeof(shahash)) == WALLY_OK
        && wally_ec_sig_from_bytes(pin_privatekey, pin_privatekey_len, shahash, sizeof(shahash),
               EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE, sig, sig_len)
            == WALLY_OK;

    SENSITIVE_POP(shadata);
    SENSITIVE_POP(shahash);
    return ret;
}

static bool assemble_reply_data(
    const pin_keys_t* pinkeys, const uint8_t* payload, const size_t payload_len, char* output, const size_t output_len)
{
    JADE_ASSERT(pinkeys);
    JADE_ASSERT(payload);
    JADE_ASSERT(payload_len <= CLIENT_REQUEST_MAX_PAYLOAD_LEN);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len > payload_len);

    // Concatentate fields and base-64 encode
    uint8_t data[sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter) + CLIENT_REQUEST_MAX_PAYLOAD_LEN];
    const size_t data_len = sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter) + payload_len;
    JADE_ASSERT(data_len <= sizeof(data));
    JADE_ASSERT(output_len > data_len);

    memcpy(data, pinkeys->cke, sizeof(pinkeys->cke));
    memcpy(data + sizeof(pinkeys->cke), pinkeys->replay_counter, sizeof(pinkeys->replay_counter));
    memcpy(data + sizeof(pinkeys->cke) + sizeof(pinkeys->replay_counter), payload, payload_len);

    size_t written = 0;
    if (mbedtls_base64_encode((uint8_t*)output, output_len, &written, data, data_len) || !written) {
        JADE_LOGE("Error encoding to base64: %u", written);
        return false;
    }
    JADE_ASSERT(written < output_len);

    // Append nul-terminator and return true
    output[written] = '\0';
    return true;
}

// Dance with the pinserver to obtain the final aes-key.
// Compute shared secrets, fetch server key, and then compute final aes key.
static pinserver_result_t pinserver_interaction(jade_process_t* process, const uint8_t* pin, const size_t pin_len,
    const char* document, const bool pass_client_entropy, uint8_t* finalaes, const size_t finalaes_len)
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
    uint8_t payload[CLIENT_REQUEST_MAX_PAYLOAD_LEN];

    SENSITIVE_PUSH(&pinkeys, sizeof(pinkeys));
    SENSITIVE_PUSH(pin_privatekey, sizeof(pin_privatekey));
    SENSITIVE_PUSH(pinsecret, sizeof(pinsecret));
    SENSITIVE_PUSH(entropy, sizeof(entropy));
    SENSITIVE_PUSH(sig, sizeof(sig));

    // Start the ecdh and derive the ephemeral encryption keys
    pinserver_result_t retval = generate_ephemeral_pinkeys(&pinkeys);
    if (retval.result != SUCCESS) {
        goto cleanup;
    }

    // Generate, sign, encrypt and hmac the pin data to send
    JADE_LOGI("Generating pinserver payload");
    get_random(entropy, sizeof(entropy));
    const size_t entropy_len = pass_client_entropy ? sizeof(entropy) : 0;

    size_t written = 0;
    char data[2 * (sizeof(pinkeys.cke) + sizeof(pinkeys.replay_counter) + sizeof(payload))]; // sufficient
    if (!storage_get_pin_privatekey(pin_privatekey, sizeof(pin_privatekey))
        || !get_pin_secret(pin, pin_len, pin_privatekey, sizeof(pin_privatekey), pinsecret, sizeof(pinsecret))
        || !sign_payload(pin_privatekey, sizeof(pin_privatekey), &pinkeys, pinsecret, sizeof(pinsecret), entropy,
            entropy_len, sig, sizeof(sig))
        || !encrypt_payload(&pinkeys, pinsecret, sizeof(pinsecret), entropy, entropy_len, sig, sizeof(sig), payload,
            sizeof(payload), &written)
        || !assemble_reply_data(&pinkeys, payload, written, data, sizeof(data))) {
        // Internal failure
        retval.result = FAILURE;
        retval.errorcode = CBOR_RPC_INTERNAL_ERROR;
        retval.message = "Failed to create Oracle message content";
        goto cleanup;
    }

    // Build and send cbor reply
    const pin_data_t pin_data = { .document = document, .on_reply = "pin", .data = data };
    jade_process_reply_to_message_result(process->ctx, &pin_data, http_post_reply);

    // Get the server's aes key for the given pin/key data
    uint8_t serverkey[AES_KEY_LEN_256];
    retval = handle_pin(process, &pinkeys, serverkey, sizeof(serverkey));
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
    const char* document, const bool pass_client_entropy, uint8_t* finalaes, const size_t finalaes_len)
{
    // pinserver interaction only happens atm as a result of a call to 'auth_user'
    ASSERT_CURRENT_MESSAGE(process, "auth_user");

    while (true) {
        // Do the pinserver interaction dance, and get the resulting aes-key
        const pinserver_result_t pir
            = pinserver_interaction(process, pin, pin_len, document, pass_client_entropy, finalaes, finalaes_len);

#ifndef CONFIG_DEBUG_UNATTENDED_CI
        // If a) the error is 'retry-able' and b) the user elects to retry, then loop and try again
        // (In a CI build no GUI, so assume 'no' and return the error immediately.)
        if (pir.result == CAN_RETRY) {
            const char* question[] = { "Failed communicating", "with Oracle - retry ?" };
            if (await_yesno_activity("Network Error", question, 2, true, NULL)) {
                const char* message[] = { "Retrying..." };
                display_message_activity(message, 1);
                continue;
            }
        }
#endif
        // If failed or abandoned, send reject message
        // NOTE: 'CANCELLED' is deliberately 'silent'
        if (pir.result != SUCCESS && pir.result != CANCELLED) {
            JADE_LOGE("Failed to complete pinserver interaction");
            jade_process_reject_message(process, pir.errorcode, pir.message, NULL);

            const char* message[] = { "Network or server", "error" };
            await_error_activity(message, 2);
            return false;
        }

        // Otherwise if all good, return true
        return pir.result == SUCCESS;
    }
}

// Interact with the pinserver to get the server's key
// Then return the final aes key.
bool pinclient_get(
    jade_process_t* process, const uint8_t* pin, const size_t pin_len, uint8_t* finalaes, const size_t finalaes_len)
{
    JADE_LOGI("Fetching pinserver data");
    const bool pass_client_entropy = false; // not required for 'get'
    return get_pinserver_aeskey(
        process, pin, pin_len, PINSERVER_DOC_GET_PIN, pass_client_entropy, finalaes, finalaes_len);
}

// Interact with the pinserver to get a new server key
// Then return the (new) final aes key.
bool pinclient_set(
    jade_process_t* process, const uint8_t* pin, const size_t pin_len, uint8_t* finalaes, const size_t finalaes_len)
{
    JADE_LOGI("Setting new pinserver data");
    const bool pass_client_entropy = true; // mandatory for 'set pin' (as new aes key is created)
    return get_pinserver_aeskey(
        process, pin, pin_len, PINSERVER_DOC_SET_PIN, pass_client_entropy, finalaes, finalaes_len);
}
