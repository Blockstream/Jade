
#include "rsa.h"
#include "jade_assert.h"
#include "keychain.h"
#include "random.h"
#include "sensitive.h"
#include "utils/shake256.h"
#include "wallet.h"

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

// Function to get bip85-generated rsa context
// See: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
static bool get_bip85_rsa_ctx(const size_t key_bits, const size_t index, mbedtls_rsa_context* output)
{
    JADE_ASSERT(key_bits <= MAX_RSA_GEN_KEY_LEN);
    JADE_ASSERT(RSA_KEY_SIZE_VALID(key_bits));
    // index can be 0
    JADE_ASSERT(output);

    JADE_ASSERT(keychain_get());
    JADE_LOGI("Deriving BIP85 RSA context for index %u, key length: %u", index, key_bits);

    uint8_t entropy[HMAC_SHA512_LEN];
    size_t entropy_len = 0;
    wallet_get_bip85_rsa_entropy(key_bits, index, entropy, sizeof(entropy), &entropy_len);
    JADE_ASSERT(entropy_len == 64);

    struct shake256_ctx sctx = {};
    shake256_init(&sctx, entropy, entropy_len);
    if (mbedtls_rsa_gen_key(output, shake256_mbedtls_rnd_cb, &sctx, key_bits, 65537) != 0) {
        JADE_LOGE("Failed to create/setup key from rsa context");
        return false;
    }

    return true;
}

// Function to get bip85-generated rsa key pem
bool rsa_get_bip85_pubkey_pem(const size_t key_bits, const size_t index, char* output, const size_t output_len)
{
    JADE_ASSERT(key_bits <= MAX_RSA_GEN_KEY_LEN);
    JADE_ASSERT(RSA_KEY_SIZE_VALID(key_bits));
    // index can be 0
    JADE_ASSERT(output);
    JADE_ASSERT(output_len);

    JADE_ASSERT(keychain_get());
    bool retval = false;

    mbedtls_rsa_context rsa = {};
    mbedtls_rsa_init(&rsa);
    SENSITIVE_PUSH(&rsa, sizeof(rsa));

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    SENSITIVE_PUSH(&pk, sizeof(pk));

    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        JADE_LOGE("Failed to create/setup key from rsa context");
        goto cleanup;
    }

    if (!get_bip85_rsa_ctx(key_bits, index, &rsa)) {
        JADE_LOGE("Failed to generate bip85 rsa ctx");
        goto cleanup;
    }

    if (mbedtls_rsa_copy(mbedtls_pk_rsa(pk), &rsa) != 0) {
        JADE_LOGE("Failed to copy key from rsa context");
        goto cleanup;
    }

    if (mbedtls_pk_write_pubkey_pem(&pk, (uint8_t*)output, output_len) != 0) {
        JADE_LOGE("Failed to write pubkey to buffer of length %u", output_len);
        goto cleanup;
    }

    retval = true;

cleanup:
    mbedtls_pk_free(&pk);
    SENSITIVE_POP(&pk);

    mbedtls_rsa_free(&rsa);
    SENSITIVE_POP(&rsa);

    return retval;
}

// Function to get bip85-generated rsa key pem
bool rsa_bip85_key_sign_digests(const size_t key_bits, const size_t index, const rsa_signing_digest_t* digests,
    const size_t digests_len, rsa_signature_t* signatures, const size_t signatures_len)
{
    JADE_ASSERT(key_bits <= MAX_RSA_GEN_KEY_LEN);
    JADE_ASSERT(RSA_KEY_SIZE_VALID(key_bits));
    // index can be 0
    JADE_ASSERT(digests);
    JADE_ASSERT(digests_len);
    JADE_ASSERT(signatures);
    JADE_ASSERT(signatures_len == digests_len);

    JADE_ASSERT(keychain_get());
    bool retval = false;

    mbedtls_rsa_context rsa = {};
    mbedtls_rsa_init(&rsa);
    SENSITIVE_PUSH(&rsa, sizeof(rsa));

    if (!get_bip85_rsa_ctx(key_bits, index, &rsa)) {
        JADE_LOGE("Failed to generate bip85 rsa ctx");
        goto cleanup;
    }

    for (size_t i = 0; i < digests_len; ++i) {
        JADE_LOGI("RSA signing digest %u/%u", i + 1, digests_len);
        const rsa_signing_digest_t* const digest = digests + i;
        rsa_signature_t* const sigout = signatures + i;

        if (digest->digest_len != SHA256_LEN) {
            JADE_LOGE("Unexpected digest len: %u", digest->digest_len);
            goto cleanup;
        }

        // Use pkcs#21/pss non-deterministic signatures
        mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

        // NOTE: For CI we use a deterministic entropy source so we do get deterministic signatures!
        // (Uses the 'master unblinding key' to seed the shake256 prng as it's fixed for the wallet
        // and is of the expected size (64-bytes))
        // (An alternative would be use to mbedtls_rsa_pkcs1_sign() for CI, which produces deterministic signatures)
#ifdef CONFIG_DEBUG_UNATTENDED_CI
        struct shake256_ctx sctx = {};
        shake256_init(&sctx, keychain_get()->master_unblinding_key, sizeof(keychain_get()->master_unblinding_key));
        const int rc = mbedtls_rsa_rsassa_pss_sign(&rsa, shake256_mbedtls_rnd_cb, &sctx, MBEDTLS_MD_SHA256,
            digest->digest_len, digest->digest, sigout->signature);
#else
        const int rc = mbedtls_rsa_rsassa_pss_sign(
            &rsa, random_mbedtls_cb, NULL, MBEDTLS_MD_SHA256, digest->digest_len, digest->digest, sigout->signature);
#endif
        if (rc) {
            JADE_LOGE("Failed to make RSA signature: %d", rc);
            goto cleanup;
        }
        sigout->signature_len = mbedtls_rsa_get_len(&rsa);
    }
    retval = true;

cleanup:
    mbedtls_rsa_free(&rsa);
    SENSITIVE_POP(&rsa);

    return retval;
}
