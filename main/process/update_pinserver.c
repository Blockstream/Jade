#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../qrmode.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include <wally_crypto.h>

#include "process_utils.h"

bool show_pinserver_details_activity(
    const char* urlA, const char* urlB, const char* pubkeyhex, bool initial_confirmation);
bool show_pinserver_certificate_activity(const char* cert_hash_hex, bool initial_confirmation);

// Default pinserver public key
extern const uint8_t server_public_key_start[] asm("_binary_pinserver_public_key_pub_start");

static const char URL_PROTOCOL_HTTP[] = { 'h', 't', 't', 'p', ':', '/', '/' };
static const char URL_PROTOCOL_HTTPS[] = { 'h', 't', 't', 'p', 's', ':', '/', '/' };

#define PROTOCOL_IS(protocol, url, len) (len > sizeof(protocol) && !strncmp(url, protocol, sizeof(protocol)))
#define VALID_PROTOCOL(url, len) (PROTOCOL_IS(URL_PROTOCOL_HTTP, url, len) || PROTOCOL_IS(URL_PROTOCOL_HTTPS, url, len))

void show_pinserver_details(void)
{
    // Load custom pinserver details from storage
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    char urlA[MAX_PINSVR_URL_LENGTH] = { 0 };
    char urlB[MAX_PINSVR_URL_LENGTH] = { 0 };
    char cert[MAX_PINSVR_CERTIFICATE_LENGTH] = { 0 };
    size_t urlA_len = 0, urlB_len = 0, cert_len = 0;
    const bool have_pubkey = storage_get_pinserver_pubkey(pubkey, sizeof(pubkey));
    const bool have_urlA = storage_get_pinserver_urlA(urlA, sizeof(urlA), &urlA_len) && urlA_len;
    const bool have_urlB = storage_get_pinserver_urlB(urlB, sizeof(urlB), &urlB_len) && urlB_len;
    const bool have_cert = storage_get_pinserver_cert(cert, sizeof(cert), &cert_len) && cert_len;

    // If no pinserver set, show the help screen
    if (!have_pubkey && !have_urlA && !have_urlB && !have_cert) {
        const char* message[] = { "Custom Oracle not set" };
        await_message_activity(message, 1);
        return;
    }

    // Show Pinserver details if present
    if (have_pubkey || have_urlA || have_urlB) {
        char* pubkey_hex = NULL;
        if (have_pubkey) {
            JADE_WALLY_VERIFY(wally_hex_from_bytes(pubkey, sizeof(pubkey), &pubkey_hex));
        }
        const bool initial_confirmation = false;
        show_pinserver_details_activity(urlA, urlB, pubkey_hex, initial_confirmation);

        if (pubkey_hex) {
            JADE_WALLY_VERIFY(wally_free_string(pubkey_hex));
        }
    }

    // Show certificate details if present
    if (have_cert) {
        char* cert_hash_hex = NULL;
        uint8_t cert_hash[SHA256_LEN];
        JADE_WALLY_VERIFY(wally_sha256((uint8_t*)cert, cert_len, cert_hash, sizeof(cert_hash)));
        JADE_WALLY_VERIFY(wally_hex_from_bytes(cert_hash, sizeof(cert_hash), &cert_hash_hex));

        const bool confirming_details = false;
        show_pinserver_certificate_activity(cert_hash_hex, confirming_details);
        JADE_WALLY_VERIFY(wally_free_string(cert_hash_hex));
    }
}

// Update the pinserver details from the passed message parameters
int update_pinserver(const CborValue* const params, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_INIT_OUT_PPTR(errmsg);

    char urlA[MAX_PINSVR_URL_LENGTH] = { 0 };
    char urlB[MAX_PINSVR_URL_LENGTH] = { 0 };
    char cert[MAX_PINSVR_CERTIFICATE_LENGTH] = { 0 };

    const uint8_t* pubkey;
    size_t pubkey_len = 0;

    int retval = CBOR_RPC_BAD_PARAMETERS;

    // 1. update or erase the pinserver details
    bool reset_details = false;
    rpc_get_boolean("reset_details", params, &reset_details);

    size_t urlA_len = 0, urlB_len = 0;
    rpc_get_string("urlA", sizeof(urlA), params, urlA, &urlA_len);
    rpc_get_string("urlB", sizeof(urlB), params, urlB, &urlB_len);
    rpc_get_bytes_ptr("pubkey", params, &pubkey, &pubkey_len);

    if (rpc_has_field_data("urlA", params) && !VALID_PROTOCOL(urlA, urlA_len)) {
        *errmsg = "Empty or invalid first URL";
        goto cleanup;
    }
    if (urlB_len && !VALID_PROTOCOL(urlB, urlB_len)) {
        *errmsg = "Invalid second URL";
        goto cleanup;
    }
    if (urlB_len && !urlA_len) {
        *errmsg = "Cannot set only second URL";
        goto cleanup;
    }
    if ((urlA_len || pubkey) && reset_details) {
        *errmsg = "Cannot set and reset details";
        goto cleanup;
    }
    if (pubkey) {
        if (!urlA_len) {
            *errmsg = "Cannot set pubkey without URL";
            goto cleanup;
        }
        if (pubkey_len != EC_PUBLIC_KEY_LEN || wally_ec_public_key_verify(pubkey, pubkey_len) != WALLY_OK) {
            *errmsg = "Invalid Oracle pubkey";
            goto cleanup;
        }
    }

#ifndef CONFIG_DEBUG_MODE
    if (keychain_has_pin()) {
        // Check that we are not trying to update the pinserver pubkey on a Jade unit
        // that already has a wallet set up/persisted in flash.
        // NOTE: we do allow an update of just the url/certs, as this may be a url change
        // that still connects to the same backend pinserver instance.
        uint8_t user_pubkey[EC_PUBLIC_KEY_LEN];
        const bool have_user_pubkey = storage_get_pinserver_pubkey(user_pubkey, sizeof(user_pubkey));

        // Cannot reset a non-default pubkey to the default value
        if (reset_details && have_user_pubkey && memcmp(server_public_key_start, user_pubkey, sizeof(user_pubkey))) {
            *errmsg = "Cannot update initialized unit";
            goto cleanup;
        }

        // Cannot set new pubkey unless effectively unchanged
        const uint8_t* effective_pubkey = have_user_pubkey ? user_pubkey : server_public_key_start;
        if (pubkey && memcmp(effective_pubkey, pubkey, pubkey_len)) {
            *errmsg = "Cannot update initialized unit";
            goto cleanup;
        }
    }
#endif // CONFIG_DEBUG_MODE

    if (urlA_len) {
        char* pubkey_hex = NULL;
        if (pubkey && pubkey_len > 0) {
            JADE_WALLY_VERIFY(wally_hex_from_bytes(pubkey, pubkey_len, &pubkey_hex));
        }

        const bool initial_confirmation = true;
        const bool confirmed = show_pinserver_details_activity(urlA, urlB, pubkey_hex, initial_confirmation);

        if (pubkey_hex) {
            JADE_WALLY_VERIFY(wally_free_string(pubkey_hex));
        }

        if (!confirmed) {
            JADE_LOGW("User declined to confirm pinserver details");
            *errmsg = "User declined to confirm Oracle details";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
    } else if (reset_details) {
        const char* message[] = { "Reset Oracle details?" };
        if (!await_yesno_activity("Reset Oracle", message, 1, false, NULL)) {
            JADE_LOGW("User declined to confirm resetting pinserver details");
            *errmsg = "User declined to confirm resetting Oracle details";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
    }

    // 2. update or erase the certificate
    bool reset_certificate = false;
    rpc_get_boolean("reset_certificate", params, &reset_certificate);
    const bool set_certificate = rpc_has_field_data("certificate", params);

    if (set_certificate && reset_certificate) {
        *errmsg = "Cannot set and reset certificate";
        goto cleanup;
    }

    if (set_certificate) {
        size_t cert_len = 0;
        rpc_get_string("certificate", sizeof(cert), params, cert, &cert_len);

        char* cert_hash_hex = NULL;
        if (cert_len > 0) {
            uint8_t cert_hash[SHA256_LEN];
            JADE_WALLY_VERIFY(wally_sha256((uint8_t*)cert, cert_len, cert_hash, sizeof(cert_hash)));
            JADE_WALLY_VERIFY(wally_hex_from_bytes(cert_hash, sizeof(cert_hash), &cert_hash_hex));
        }

        const bool initial_confirmation = true;
        const bool confirmed = show_pinserver_certificate_activity(cert_hash_hex, initial_confirmation);

        if (cert_hash_hex) {
            JADE_WALLY_VERIFY(wally_free_string(cert_hash_hex));
        }

        if (!confirmed) {
            JADE_LOGW("User declined to confirm pinserver certificate");
            *errmsg = "User declined to confirm Oracle certificate";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
    } else if (reset_certificate) {
        const char* question[] = { "Reset Oracle", "certificate?" };
        if (!await_yesno_activity("Certificate", question, 2, false, NULL)) {
            JADE_LOGW("User declined to confirm resetting pinserver certificate");
            *errmsg = "User declined to confirm resetting Oracle certificate";
            retval = CBOR_RPC_USER_CANCELLED;
            goto cleanup;
        }
    }

    // Ok, now user confirmed actions, actually set the pinserver details in storage
    if (urlA_len) {
        JADE_LOGI("Setting user pinserver details");
        if (!storage_set_pinserver_details(urlA, urlB, pubkey, pubkey_len)) {
            JADE_LOGE("Failed to persist pinserver details");
            *errmsg = "Failed to persist Oracle details";
            retval = CBOR_RPC_INTERNAL_ERROR;
            goto cleanup;
        }
    } else if (reset_details) {
        JADE_LOGI("Erasing user pinserver details - resetting to default");
        if (!storage_erase_pinserver_details()) {
            JADE_LOGE("Failed to erase pinserver details");
            *errmsg = "Failed to erase Oracle details";
            retval = CBOR_RPC_INTERNAL_ERROR;
            goto cleanup;
        }
    }

    if (set_certificate) {
        JADE_LOGI("Setting user pinserver certificate");
        if (!storage_set_pinserver_cert(cert)) {
            JADE_LOGE("Failed to persist pinserver certificate");
            *errmsg = "Failed to persist Oracle certificate";
            retval = CBOR_RPC_INTERNAL_ERROR;
            goto cleanup;
        }
    } else if (reset_certificate) {
        JADE_LOGI("Erasing user pinserver certificate - resetting to default");
        if (!storage_erase_pinserver_cert()) {
            JADE_LOGE("Failed to erase pinserver certificate");
            *errmsg = "Failed to erase Oracle certificate";
            retval = CBOR_RPC_INTERNAL_ERROR;
            goto cleanup;
        }
    }

    // ok - all good
    retval = 0;

cleanup:
    return retval;
}

bool reset_pinserver(void)
{
    JADE_ASSERT(!keychain_has_pin());

    JADE_LOGI("Erasing user pinserver details and certificate - resetting to default");
    bool retval = true;

    if (!storage_erase_pinserver_details()) {
        JADE_LOGE("Failed to erase pinserver details");
        retval = false;
    }
    if (!storage_erase_pinserver_cert()) {
        JADE_LOGE("Failed to erase pinserver certificate");
        retval = false;
    }
    return retval;
}

void update_pinserver_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "update_pinserver");
    GET_MSG_PARAMS(process);

    const char* errmsg = NULL;
    const int errcode = update_pinserver(&params, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    // Reply ok
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
