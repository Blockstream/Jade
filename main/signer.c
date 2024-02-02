
#include "signer.h"
#include "jade_assert.h"
#include "wallet.h"

#include <sodium/utils.h>

// Walks the signers and validates - this wallet must have at least one xpub and it must be correct
bool validate_signers(const signer_t* signers, const size_t num_signers, const bool accept_string_path,
    const uint8_t* wallet_fingerprint, const size_t wallet_fingerprint_len, size_t* total_num_path_elements)
{
    JADE_INIT_OUT_SIZE(total_num_path_elements);

    if (!signers || !num_signers || num_signers > MAX_ALLOWED_SIGNERS || !wallet_fingerprint
        || wallet_fingerprint_len != BIP32_KEY_FINGERPRINT_LEN) {
        return false;
    }

    bool bFound = false;
    for (size_t i = 0; i < num_signers; ++i) {
        const signer_t* signer = signers + i;

        // Check additional 'path' (after the xpub) contains no hardened elements
        if (signer->path_is_string) {
            if (!accept_string_path) {
                JADE_LOGE("Unexpected string path for signer %d: %s", i, signer->path_str);
                return false;
            }

            uint32_t features = 0;
            if (bip32_path_str_get_features(signer->path_str, &features) != WALLY_OK
                || (features & BIP32_PATH_IS_HARDENED)) {
                JADE_LOGE("Suspect path string for signer %d: %s", i, signer->path_str);
                return false;
            }
        } else {
            for (size_t j = 0; j < signer->path_len; ++j) {
                if (signer->path[j] & BIP32_INITIAL_HARDENED_CHILD) {
                    JADE_LOGE("Found hardened path %lu at pos %d in signer %d", signer->path[j], j, i);
                    return false;
                }
            }
        }

        // Check all given xpubs can be parsed
        const uint32_t flags = BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH;
        struct ext_key hdkey_provided;
        if (!wallet_derive_from_xpub(signer->xpub, NULL, 0, flags, &hdkey_provided)) {
            JADE_LOGE("Cannot deserialise xpub for derivation path (signer %d)", i);
            return false;
        }

        // See if signer matches this wallet (by fingerprint)
        if (!sodium_memcmp(wallet_fingerprint, signer->fingerprint, wallet_fingerprint_len)) {
            // This signer has our fingerprint - check xpub provided
            // NOTE: because some 3rd-party apps provide xpubs which are slightly incorrect in their ancilliary
            // metadata fields, we can't strictly compare xpub strings without affecting compatabililty.
            // Instead we deserialise the provided xpub string and compare pubkey and chaincode only.
            // NOTE: a mismatch here is not a hard fail as could be a fingerprint clash with another signer
            struct ext_key hdkey_calculated;
            if (!wallet_get_hdkey(signer->derivation, signer->derivation_len, flags, &hdkey_calculated)) {
                JADE_LOGE("Cannot derive key for derivation path (signer %d)", i);
                return false;
            }

            // Compare vital fields 'pub_key' and 'chain_code'
            // NOTE: a mismatch here is not a hard fail as could be a fingerprint clash with another signer
            if (!sodium_memcmp(hdkey_provided.pub_key, hdkey_calculated.pub_key, sizeof(hdkey_calculated.pub_key))
                && !sodium_memcmp(
                    hdkey_provided.chain_code, hdkey_calculated.chain_code, sizeof(hdkey_calculated.chain_code))) {
                // We have found our signer in the quorum
                JADE_LOGI("Found our signer (signer %d)", i);
                bFound = true;
            }
        }

        // Count the total number of path elements across all signers
        *total_num_path_elements += signer->derivation_len;
        *total_num_path_elements += signer->path_len;
    }

    return bFound;
}
