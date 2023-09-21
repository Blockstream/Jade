#ifndef SIGNER_H_
#define SIGNER_H_

#include "utils/cbor_rpc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The maximum number of script signers supported
#define MAX_ALLOWED_SIGNERS 15

// Signer details passed in during multisig registration
typedef struct {
    uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];

    // The derivation is the path to get from the root/fingerprint to
    // the xpub provided.  Only actually needs to be present and correct
    // for this wallet's xpub - as will be used to verify the xpub.
    uint32_t derivation[MAX_PATH_LEN];
    size_t derivation_len;

    // Should be sufficient as all xpubs should be <= 112
    char xpub[120];
    size_t xpub_len;

    // This is any fixed path always applied after the given xpub, but
    // before any variable path suffix provided on a per-call basis.
    // Can be expressed as a string where contains multi-path or wildcards.
    bool path_is_string;
    union {
        uint32_t path[MAX_PATH_LEN];
        char path_str[MAX_PATH_LEN * sizeof(uint32_t)];
    };
    // Can refer to number of elements in numeric path array or length of path string
    size_t path_len;
} signer_t;

bool validate_signers(const signer_t* signers, size_t num_signers, bool accept_string_path,
    const uint8_t* wallet_fingerprint, size_t wallet_fingerprint_len, size_t* total_num_path_elements);

#endif /* SIGNER_H_ */