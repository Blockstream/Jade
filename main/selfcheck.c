#include "selfcheck.h"

#include <sdkconfig.h>
#include <string.h>
#include <wally_bip32.h>

#include "jade_assert.h"
#include "keychain.h"
#include "random.h"
#include "storage.h"
#include <sodium/crypto_verify_64.h>
#include <sodium/utils.h>

static const char TEST_MNEMONIC[] = "fish inner face ginger orchard permit useful method fence kidney chuckle party "
                                    "favorite sunset draw limb science crane oval letter slot invite sadness banana";
static const char SERVICE_PATH_HEX[] = "00c9678fbd9d9f6a96bd43221d56733b5aba8f528487602b894e72d0f56e380f7d145b65639db7e"
                                       "e4f528a3fcfb8277b0cbbea00ef64767a531e9a447cacbfbc";

#define FAIL()                                                                                                         \
    {                                                                                                                  \
        JADE_LOGE("SELFCHECK FAILURE@%d", __LINE__);                                                                   \
        return false;                                                                                                  \
    }

bool debug_selfcheck(void)
{
    keychain_t keydata;
    char* mnemonic = NULL;

    size_t written = 0;
    uint8_t expected_service_path[HMAC_SHA512_LEN];
    const int ret
        = wally_hex_to_bytes(SERVICE_PATH_HEX, expected_service_path, sizeof(expected_service_path), &written);
    if (ret != WALLY_OK || written != HMAC_SHA512_LEN) {
        FAIL();
    }
    bool val = keychain_derive(TEST_MNEMONIC, NULL, &keydata);
    if (!val) {
        FAIL();
    }
    if (crypto_verify_64(keydata.service_path, expected_service_path) != 0) {
        FAIL();
    }

    // Check 12-word mnemonic generation
    keychain_get_new_mnemonic(&mnemonic, 12);
    JADE_ASSERT(mnemonic);
    val = keychain_derive(mnemonic, "passphrase12", &keydata);
    if (!val) {
        wally_free_string(mnemonic);
        FAIL();
    }
    val = wally_free_string(mnemonic);
    if (val != WALLY_OK) {
        FAIL();
    }

    // Check 24-word mnemonic generation
    keychain_get_new_mnemonic(&mnemonic, 24);
    JADE_ASSERT(mnemonic);
    val = keychain_derive(mnemonic, "passphrase24", &keydata);
    if (!val) {
        wally_free_string(mnemonic);
        FAIL();
    }
    val = wally_free_string(mnemonic);
    if (val != WALLY_OK) {
        FAIL();
    }

    // Check encryption/decryption
    unsigned char aeskey[AES_KEY_LEN_256];
    get_random(aeskey, AES_KEY_LEN_256);
    keychain_set(&keydata, 0, false);
    val = keychain_store_encrypted(aeskey, sizeof(aeskey), &keydata);
    if (!val) {
        FAIL();
    }
    if (!keychain_has_pin()) {
        FAIL();
    }
    if (storage_get_counter() != 3) {
        FAIL();
    }
    keychain_t keydata2;
    val = keychain_load_cleartext(aeskey, sizeof(aeskey), &keydata2);
    if (!val) {
        FAIL();
    }
    if (!keychain_has_pin()) {
        FAIL();
    }
    if (storage_get_counter() != 3) {
        FAIL();
    }
    if (crypto_verify_64(keydata.service_path, keydata2.service_path) != 0) {
        FAIL();
    }
    if (crypto_verify_64(keydata.master_unblinding_key, keydata2.master_unblinding_key) != 0) {
        FAIL();
    }
    char* base58res = NULL;
    char* base58res_copy = NULL;
    val = bip32_key_to_base58(&keydata.xpriv, BIP32_FLAG_KEY_PRIVATE, &base58res);
    if (val != WALLY_OK) {
        FAIL();
    }
    val = bip32_key_to_base58(&keydata2.xpriv, BIP32_FLAG_KEY_PRIVATE, &base58res_copy);
    int len = strlen(base58res);
    if (val != WALLY_OK) {
        FAIL();
    }
    if (sodium_memcmp(base58res, base58res_copy, len) != 0) {
        FAIL();
    }

    // Free/erase the keychain, then reload from nvs
    // BUT! pass the wrong aes-key (ie. wrong PIN)
    unsigned char wrongkey[AES_KEY_LEN_256];
    get_random(wrongkey, AES_KEY_LEN_256);
    for (size_t i = 3; i > 0; --i) {
        if (storage_get_counter() != i) {
            FAIL();
        }

        if (!keychain_has_pin()) {
            FAIL();
        }

        val = keychain_load_cleartext(wrongkey, sizeof(wrongkey), &keydata2);
        if (val) {
            FAIL();
        }

        if (storage_get_counter() + 1 != i) {
            FAIL();
        }
    }

    if (keychain_has_pin()) {
        FAIL();
    }

    val = keychain_load_cleartext(aeskey, sizeof(aeskey), &keydata2);
    if (val) {
        FAIL();
    }

    wally_free_string(base58res);
    wally_free_string(base58res_copy);

    // PASS !
    return true;
}
