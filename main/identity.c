#ifndef AMALGAMATED_BUILD
#include "identity.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "random.h"
#include "sensitive.h"
#include "utils/util.h"

#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <string.h>

#define IDENTITY_PATH_LEN 5

#define SLIP13_PATH_PREFIX (BIP32_INITIAL_HARDENED_CHILD | 13)
#define SLIP17_PATH_PREFIX (BIP32_INITIAL_HARDENED_CHILD | 17)

static const uint8_t SSH_NIST_HMAC_KEY[] = { 'N', 'i', 's', 't', '2', '5', '6', 'p', '1', ' ', 's', 'e', 'e', 'd' };

// Interpret 4 bytes as a uint32_t path element, and set the 'hardened' bit
// NOTE: 'bytes' ptr must be 4-byte aligned
#define HARDENED_PATH_ELEMENT(bytes) (BIP32_INITIAL_HARDENED_CHILD | *((uint32_t*)(bytes)))

// Deduce the default (only?) curve to use from the identity protocol
static inline mbedtls_ecp_group_id get_curve_group_id(const char* curve_name, const size_t curve_name_len)
{
    mbedtls_ecp_group_id curve_group_id = MBEDTLS_ECP_DP_NONE;
    if (is_identity_curve_nist256p1(curve_name, curve_name_len)) {
        curve_group_id = MBEDTLS_ECP_DP_SECP256R1;
    }
    // add more curves ...
    return curve_group_id;
}

static inline size_t get_key_derivation_prefix(const char* type, const size_t type_len)
{
    size_t prefix = 0;
    if (is_key_type_slip0013(type, type_len)) {
        prefix = SLIP13_PATH_PREFIX;
    } else if (is_key_type_slip0017(type, type_len)) {
        prefix = SLIP17_PATH_PREFIX;
    }
    // more types ??
    return prefix;
}

// Translate an identity string and index into a slip13/slip17 'identity-hash'
static void get_identity_hash(
    const char* identity, const size_t identity_len, const uint32_t index, uint8_t* output, const size_t output_len)
{
    JADE_ASSERT(identity);
    JADE_ASSERT(identity_len);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len == SHA256_LEN);

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    JADE_ZERO_VERIFY(mbedtls_sha256_starts(&ctx, 0));
    JADE_ZERO_VERIFY(mbedtls_sha256_update(&ctx, (uint8_t*)&index, sizeof(index)));
    JADE_ZERO_VERIFY(mbedtls_sha256_update(&ctx, (uint8_t*)identity, identity_len));
    JADE_ZERO_VERIFY(mbedtls_sha256_finish(&ctx, output));
    mbedtls_sha256_free(&ctx);
}

// Translate an identity hash into a bip32 path (eg. slip13/slip17)
static void get_path_from_hash(const size_t slip_prefix, const uint8_t* identity_hash, const size_t identity_hash_len,
    uint32_t* path, const size_t path_len)
{
    JADE_ASSERT(identity_hash);
    JADE_ASSERT((size_t)identity_hash % 4 == 0); // 4-byte aligned
    JADE_ASSERT(identity_hash_len == SHA256_LEN);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len == IDENTITY_PATH_LEN);

    path[0] = slip_prefix;
    path[1] = HARDENED_PATH_ELEMENT(&identity_hash[0]);
    path[2] = HARDENED_PATH_ELEMENT(&identity_hash[4]);
    path[3] = HARDENED_PATH_ELEMENT(&identity_hash[8]);
    path[4] = HARDENED_PATH_ELEMENT(&identity_hash[12]);
}

// Function to derive child private key from parent private key for passed curve/group.
// Special case only handles private keys and hardened path index.
// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
static void get_bip32_hardened_child(
    const mbedtls_ecp_group* grp, const struct ext_key* parent, const size_t child_index, struct ext_key* child_out)
{
    JADE_ASSERT(grp);
    JADE_ASSERT(parent);
    JADE_ASSERT(parent->version == BIP32_VER_MAIN_PRIVATE);
    JADE_ASSERT(parent->priv_key[0] == BIP32_FLAG_KEY_PRIVATE);
    JADE_ASSERT(child_index >= BIP32_INITIAL_HARDENED_CHILD);
    JADE_ASSERT(child_out);

    // NOTE: comments and logical steps takes from libwally-core function `bip32_key_from_parent()`:
    // https://github.com/ElementsProject/libwally-core/blob/master/src/bip32.c

    // Hardened: Data = 0x00 || ser256(kpar) || ser32(i))
    memcpy(child_out->priv_key, parent->priv_key, sizeof(child_out->priv_key));

    // This is the '|| ser32(i)' part of the above
    uint32_to_be(child_index, (uint8_t*)&child_out->child_num);

    // I = HMAC-SHA512(Key = cpar, Data)
    uint8_t sha[HMAC_SHA512_LEN];
    JADE_WALLY_VERIFY(wally_hmac_sha512(parent->chain_code, sizeof(parent->chain_code), child_out->priv_key,
        sizeof(child_out->priv_key) + sizeof(child_out->child_num), sha, sizeof(sha)));

    // Split I into two 32-byte sequences, IL and IR
    // The returned chain code ci is IR (i.e. the 2nd half of our hmac sha512)
    memcpy(child_out->chain_code, sha + sizeof(sha) / 2, sizeof(child_out->chain_code));

    // The returned child key ki is parse256(IL) + kpar (mod n)
    mbedtls_mpi key = { 0 }, tweak = { 0 }, tmp = { 0 };
    SENSITIVE_PUSH(&key, sizeof(key));
    SENSITIVE_PUSH(&tweak, sizeof(tweak));
    SENSITIVE_PUSH(&tmp, sizeof(tmp));
    mbedtls_mpi_init(&key);
    mbedtls_mpi_init(&tweak);
    mbedtls_mpi_init(&tmp);

    JADE_ZERO_VERIFY(mbedtls_mpi_read_binary(&key, &parent->priv_key[1], sizeof(parent->priv_key) - 1));
    JADE_ZERO_VERIFY(mbedtls_mpi_read_binary(&tweak, sha, sizeof(sha) / 2));

    JADE_ZERO_VERIFY(mbedtls_mpi_add_mpi(&tmp, &tweak, &key));
    JADE_ZERO_VERIFY(mbedtls_mpi_mod_mpi(&key, &tmp, &grp->N));

    JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&key, &child_out->priv_key[1], sizeof(child_out->priv_key) - 1));

    mbedtls_mpi_free(&key);
    mbedtls_mpi_free(&tweak);
    mbedtls_mpi_free(&tmp);
    SENSITIVE_POP(&tmp);
    SENSITIVE_POP(&tweak);
    SENSITIVE_POP(&key);

    child_out->version = BIP32_VER_MAIN_PRIVATE;
}

// Function to derive bip32 child private key from parent private key for passed curve/group.
// Special case only handles private keys and a path where all indices are hardened.
// Also assumes path length is consistent with slip13/slip17.
static void get_bip32_hardened_child_from_path(const mbedtls_ecp_group* grp, const struct ext_key* parent,
    const uint32_t* path, const size_t path_len, struct ext_key* child_out)
{
    JADE_ASSERT(grp);
    JADE_ASSERT(parent);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len == IDENTITY_PATH_LEN);
    JADE_ASSERT(child_out);

    // Since there are only 4 intermediate keys, we may as well just hold them all.
    // Seems easier than flipping between two temporaries or using memcpy(dest, src,...)
    struct ext_key intermediates[IDENTITY_PATH_LEN - 1] = { 0 };
    SENSITIVE_PUSH(&intermediates, sizeof(intermediates));
    for (size_t i = 0; i < path_len; ++i) {
        const struct ext_key* immediate_parent = i == 0 ? parent : &intermediates[i - 1];
        struct ext_key* this_child = i == path_len - 1 ? child_out : &intermediates[i];
        get_bip32_hardened_child(grp, immediate_parent, path[i], this_child);
    }
    SENSITIVE_POP(&intermediates);

    JADE_ASSERT(child_out->version == BIP32_VER_MAIN_PRIVATE);
    JADE_ASSERT(child_out->priv_key[0] == BIP32_FLAG_KEY_PRIVATE);
}

// Function to get a public/private keypair for a given identity (slip13 or slip17).
// Deduces the curve to use, given the identity protocol prefix.
static bool get_internal_keypair(const size_t slip_prefix, const char* identity, const size_t identity_len,
    const size_t index, const char* curve_name, const size_t curve_name_len, mbedtls_ecp_keypair* keypair)
{
    JADE_ASSERT(curve_name);
    JADE_ASSERT(curve_name_len > 0);
    JADE_ASSERT(identity);
    JADE_ASSERT(identity_len > 0);
    JADE_ASSERT(keypair);
    JADE_ASSERT(keychain_get());

    if (keychain_get()->seed_len == 0) {
        JADE_LOGE("No wallet seed available.");
        return false;
    }

    // Get/load the curve of interest
    const mbedtls_ecp_group_id curve_group_id = get_curve_group_id(curve_name, curve_name_len);
    if (curve_group_id == MBEDTLS_ECP_DP_NONE) {
        JADE_LOGE("Unsupported curve '%.*s'", curve_name_len, curve_name);
        return false;
    }
    // FIXME: use getters instead of MBEDTLS_PRIVATE MACRO
    JADE_ZERO_VERIFY(mbedtls_ecp_group_load(&keypair->MBEDTLS_PRIVATE(grp), curve_group_id));

    // Get the hash of the identity and index
    uint8_t identity_hash[SHA256_LEN];
    get_identity_hash(identity, identity_len, index, identity_hash, sizeof(identity_hash));

    // Get the bip32 path for that hash
    uint32_t path[IDENTITY_PATH_LEN];
    get_path_from_hash(slip_prefix, identity_hash, sizeof(identity_hash), path, IDENTITY_PATH_LEN);

    // Derive a key from this curve, for this identity/path
    struct ext_key derived = { 0 };
    struct ext_key root = { 0 };
    SENSITIVE_PUSH(&derived, sizeof(derived));
    SENSITIVE_PUSH(&root, sizeof(root));

    // Derive root/master key for this curve from the seed (use mainnet version flag as irrelevant here)
    JADE_WALLY_VERIFY(bip32_key_from_seed_custom(keychain_get()->seed, keychain_get()->seed_len, BIP32_VER_MAIN_PRIVATE,
        SSH_NIST_HMAC_KEY, sizeof(SSH_NIST_HMAC_KEY), 0, &root));

    // Use local function to run (a restricted) bip32 derivation for this curve
    get_bip32_hardened_child_from_path(&keypair->MBEDTLS_PRIVATE(grp), &root, path, IDENTITY_PATH_LEN, &derived);
    SENSITIVE_POP(&root);

    // Read the private key into the output keypair
    // NOTE: need to skip the leading 0 byte
    JADE_ZERO_VERIFY(
        mbedtls_mpi_read_binary(&keypair->MBEDTLS_PRIVATE(d), &derived.priv_key[1], sizeof(derived.priv_key) - 1));
    JADE_ZERO_VERIFY(mbedtls_ecp_check_privkey(&keypair->MBEDTLS_PRIVATE(grp), &keypair->MBEDTLS_PRIVATE(d)));
    SENSITIVE_POP(&derived);

    // Generate the public key from the private key + curve settings
    JADE_ZERO_VERIFY(mbedtls_ecp_mul(&keypair->MBEDTLS_PRIVATE(grp), &keypair->MBEDTLS_PRIVATE(Q),
        &keypair->MBEDTLS_PRIVATE(d), &keypair->MBEDTLS_PRIVATE(grp).G, random_mbedtls_cb, NULL));
    JADE_ZERO_VERIFY(mbedtls_ecp_check_pubkey(&keypair->MBEDTLS_PRIVATE(grp), &keypair->MBEDTLS_PRIVATE(Q)));

    // Sanity check
    JADE_ZERO_VERIFY(mbedtls_ecp_check_pub_priv(keypair, keypair, random_mbedtls_cb, NULL));

    return true;
}

// Function to sign challenge with the passed key
// Returns a low-s signature - not sure whether this is vital...
static bool sign_challenge(mbedtls_ecp_keypair* keypair, const uint8_t* challenge, const size_t challenge_len,
    mbedtls_mpi* pr, mbedtls_mpi* ps)
{
    JADE_ASSERT(keypair);
    JADE_ASSERT(challenge);
    JADE_ASSERT(challenge_len);
    JADE_ASSERT(pr);
    JADE_ASSERT(ps);

    // Use RFC6979 deterministic signatures
    const int ret = mbedtls_ecdsa_sign_det_ext(&keypair->MBEDTLS_PRIVATE(grp), pr, ps, &keypair->MBEDTLS_PRIVATE(d),
        challenge, challenge_len, MBEDTLS_MD_SHA256, random_mbedtls_cb, NULL);
    if (ret) {
        JADE_LOGE("mbedtls_ecdsa_sign_det_ext() failed, returned %d", ret);
        return false;
    }

    // Ensure signatures are 'low-s'.
    // Can remove if this is not vital, but having this here
    // means signatures generated are consistent with trezor.
    mbedtls_mpi tmp = { 0 };
    mbedtls_mpi_init(&tmp);

    JADE_ZERO_VERIFY(mbedtls_mpi_copy(&tmp, &keypair->MBEDTLS_PRIVATE(grp).N));
    JADE_ZERO_VERIFY(mbedtls_mpi_shift_r(&tmp, 1));

    if (mbedtls_mpi_cmp_mpi(ps, &tmp) > 0) {
        // Generated 'high' S.  Flip to low-s.
        JADE_ZERO_VERIFY(mbedtls_mpi_sub_mpi(&tmp, &keypair->MBEDTLS_PRIVATE(grp).N, ps));
        JADE_ZERO_VERIFY(mbedtls_mpi_copy(ps, &tmp));
    }
    mbedtls_mpi_free(&tmp);

    // Sanity check
    JADE_ZERO_VERIFY(mbedtls_ecdsa_verify(
        &keypair->MBEDTLS_PRIVATE(grp), challenge, challenge_len, &keypair->MBEDTLS_PRIVATE(Q), pr, ps));

    return true;
}

// Function to get the uncompressed public key for a given identity and index
// NOTE: atm this supports 'ssh://' only, using nist256p1/secp256r1
// NOTE: this api returns *uncompressed* pubkeys
bool get_identity_pubkey(const char* identity, const size_t identity_len, const size_t index, const char* curve_name,
    const size_t curve_name_len, const char* type, const size_t type_len, uint8_t* pubkey_out,
    const size_t pubkey_out_len)
{
    if (!identity || !identity_len || !curve_name || !curve_name_len || !type || !type_len || !pubkey_out
        || pubkey_out_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
        return false;
    }

    // Get a keypair and curve for this identity
    mbedtls_ecp_keypair keypair = { 0 };
    SENSITIVE_PUSH(&keypair, sizeof(keypair));
    mbedtls_ecp_keypair_init(&keypair);
    bool result = false;

    // Prefix deduced from type - ie. slip13 vs slip17
    const size_t slip_prefix = get_key_derivation_prefix(type, type_len);
    if (!slip_prefix) {
        JADE_LOGE("Unsupported key derivation type '%.*s'", type_len, type);
        return false;
    }

    if (!get_internal_keypair(slip_prefix, identity, identity_len, index, curve_name, curve_name_len, &keypair)) {
        JADE_LOGE(
            "get_identity_pubkey() failed to get key/curve for '%.*s' and index %u", identity_len, identity, index);
    } else {
        // Return the pubkey assoiciated with this identity/signature
        size_t pubkeylen = 0;
        JADE_ZERO_VERIFY(mbedtls_ecp_point_write_binary(&keypair.MBEDTLS_PRIVATE(grp), &keypair.MBEDTLS_PRIVATE(Q),
            MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkeylen, pubkey_out, pubkey_out_len));
        JADE_ASSERT(pubkeylen == pubkey_out_len);
        result = true;
    }

    mbedtls_ecp_keypair_free(&keypair);
    SENSITIVE_POP(&keypair);
    return result;
}

// Function to get the ecdh shared secret given identity, index and counterparty (uncompressed) public key
// NOTE: atm this supports 'ssh://' only, using nist256p1/secp256r1
// NOTE: this api takes *uncompressed* pubkeys
bool get_identity_shared_key(const char* identity, const size_t identity_len, const size_t index,
    const char* curve_name, const size_t curve_name_len, const uint8_t* their_pubkey, const size_t their_pubkey_len,
    uint8_t* output, const size_t output_len)
{
    if (!identity || !identity_len || !curve_name || !curve_name_len || !their_pubkey
        || their_pubkey_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN || !output || output_len != SHA256_LEN) {
        return false;
    }

    // Get a keypair and curve for this identity
    mbedtls_ecp_keypair keypair = { 0 };
    SENSITIVE_PUSH(&keypair, sizeof(keypair));
    mbedtls_ecp_keypair_init(&keypair);
    bool result = false;

    if (!get_internal_keypair(
            SLIP17_PATH_PREFIX, identity, identity_len, index, curve_name, curve_name_len, &keypair)) {
        JADE_LOGE(
            "get_identity_shared_key() failed to get key/curve for '%.*s' and index %u", identity_len, identity, index);
    } else {
        // Read the pubkey - this function only accepts uncompressed keys (points)
        mbedtls_ecp_point pubk = { 0 };
        mbedtls_ecp_point_init(&pubk);

        if (mbedtls_ecp_point_read_binary(&keypair.MBEDTLS_PRIVATE(grp), &pubk, their_pubkey, their_pubkey_len)
            || mbedtls_ecp_check_pubkey(&keypair.MBEDTLS_PRIVATE(grp), &pubk)) {
            JADE_LOGE("get_identity_shared_key() failed to read/validate public key point for curve id %d",
                keypair.MBEDTLS_PRIVATE(grp).id);
        } else {
            // Pubkey valid for deduced curve/group
            mbedtls_mpi shared_secret = { 0 };
            mbedtls_mpi_init(&shared_secret);

            const int ret = mbedtls_ecdh_compute_shared(&keypair.MBEDTLS_PRIVATE(grp), &shared_secret, &pubk,
                &keypair.MBEDTLS_PRIVATE(d), random_mbedtls_cb, NULL);
            if (ret) {
                JADE_LOGE("ecdh_compute_shared failed with %d", ret);
            } else {
                // Success - export secret to output buffer
                JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&shared_secret, output, output_len));
                result = true;
            }

            // Cleanup and return
            mbedtls_mpi_free(&shared_secret);
        }
        mbedtls_ecp_point_free(&pubk);
    }

    mbedtls_ecp_keypair_free(&keypair);
    SENSITIVE_POP(&keypair);
    return result;
}

// Function to sign an identity with a supported curve
// NOTE: atm this supports 'ssh://' and 'gpg://' - using nist256p1/secp256r1
// NOTE: this api returns *uncompressed* pubkeys
bool sign_identity(const char* identity, const size_t identity_len, const size_t index, const char* curve_name,
    const size_t curve_name_len, const uint8_t* challenge, const size_t challenge_len, uint8_t* pubkey_out,
    const size_t pubkey_out_len, uint8_t* signature_out, const size_t signature_out_len)
{
    if (!identity || !identity_len || !curve_name || !curve_name_len || !challenge || !challenge_len || !pubkey_out
        || pubkey_out_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN || !signature_out
        || signature_out_len != EC_SIGNATURE_LEN + 1) {
        return false;
    }

    // Get a keypair and curve for this identity
    mbedtls_ecp_keypair keypair = { 0 };
    SENSITIVE_PUSH(&keypair, sizeof(keypair));
    mbedtls_ecp_keypair_init(&keypair);
    bool result = false;

    if (get_internal_keypair(SLIP13_PATH_PREFIX, identity, identity_len, index, curve_name, curve_name_len, &keypair)) {
        // Return the pubkey assoiciated with this identity/signature
        size_t pubkeylen = 0;
        JADE_ZERO_VERIFY(mbedtls_ecp_point_write_binary(&keypair.MBEDTLS_PRIVATE(grp), &keypair.MBEDTLS_PRIVATE(Q),
            MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkeylen, pubkey_out, pubkey_out_len));
        JADE_ASSERT(pubkeylen == pubkey_out_len);

        // Sign the challenge with the key
        mbedtls_mpi r = { 0 }, s = { 0 };
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        // For ssh with SECP256R1 we need to sign a hash of the challenge passed
        // Otherwise we sign the passed challenge directly
        if (keypair.MBEDTLS_PRIVATE(grp).id == MBEDTLS_ECP_DP_SECP256R1
            && is_identity_protocol_ssh(identity, identity_len)) {
            uint8_t challenge_hash[SHA256_LEN];
            JADE_WALLY_VERIFY(wally_sha256(challenge, challenge_len, challenge_hash, sizeof(challenge_hash)));
            result = sign_challenge(&keypair, challenge_hash, sizeof(challenge_hash), &r, &s);
        } else {
            result = sign_challenge(&keypair, challenge, challenge_len, &r, &s);
        }

        if (result) {
            // Success - write R and S into output buffer, with leading 00
            signature_out[0] = 0x00;
            JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&r, signature_out + 1, 32));
            JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&s, signature_out + 1 + 32, 32));
        } else {
            JADE_LOGE("sign_challenge failed!");
        }

        // Cleanup and return
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    } else {
        JADE_LOGE("sign_identity() failed to get key/curve for '%.*s' and index %u", identity_len, identity, index);
    }

    mbedtls_ecp_keypair_free(&keypair);
    SENSITIVE_POP(&keypair);
    return result;
}
#endif // AMALGAMATED_BUILD
