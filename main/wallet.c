#include "wallet.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "sensitive.h"
#include "utils/network.h"

#include <stdio.h>
#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_elements.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include <mbedtls/base64.h>
#include <sodium/utils.h>

// Restrictions on GA BIP32 path elements
static const uint32_t SUBACT_ROOT = (BIP32_INITIAL_HARDENED_CHILD + 3);
static const uint32_t SUBACT_FLOOR = BIP32_INITIAL_HARDENED_CHILD;
static const uint32_t SUBACT_CEILING = (BIP32_INITIAL_HARDENED_CHILD + 16384);
static const uint32_t PATH_BRANCH = 1;
static const uint32_t MAX_PATH_PTR = 10000;

// Maximum number of csv blocks allowed in csv scripts
static const uint32_t MAX_CSV_BLOCKS_ALLOWED = 65535;

// script lengths
#define MSIG_2OFN_SCRIPT_LEN(n) (3 + (n * (EC_PUBLIC_KEY_LEN + 1)))

// CSV script len varies depending on varint 'blocks' (between 1 byte and 3 bytes)
#define CSV_MIN_SCRIPT_LEN (9 + (2 * (EC_PUBLIC_KEY_LEN + 1)) + 1 + 1)
#define CSV_MAX_SCRIPT_LEN (9 + (2 * (EC_PUBLIC_KEY_LEN + 1)) + 1 + 3)

// BTC (rather, non-liquid) uses an optimised, mini-script compatible csv script which is slightly shorter
#define CSV_MIN_SCRIPT_LEN_OPT (6 + (2 * (EC_PUBLIC_KEY_LEN + 1)) + 1 + 1)
#define CSV_MAX_SCRIPT_LEN_OPT (6 + (2 * (EC_PUBLIC_KEY_LEN + 1)) + 1 + 3)

static const char MAINNET_SERVICE_XPUB[]
    = "xpub661MyMwAqRbcGsMS1UQfLrVW52iFHhKd1WbL4BVBZt8xz8pE6oyz6La2LscN2WADtpZZXwKo4DXMbzUdxVsLYxm7f6instfCnpB3cFdbi2F";
static const char TESTNET_SERVICE_XPUB[]
    = "tpubD6NzVbkrYhZ4Y9k7T65kw2Sx9z67CzZr2Hi7w2pkKutUvm25ryvL79PqQTtDvAaYacd4z5NQTMmdJ37t8VbMVZbDY1z2rqUKLRNpVW6rGC3";
static const char LIQUID_SERVICE_XPUB[]
    = "xpub661MyMwAqRbcEZr3uYPEEP4X2bRmYXmxrcLMH8YEwLAFxonVGqstpNywBvwkUDCEZA1cd6fsLgKvb6iZP5yUtLc3G3L8WynChNJznHLaVrA";

struct ext_key MAINNET_SERVICE;
struct ext_key TESTNET_SERVICE;
struct ext_key LIQUID_SERVICE;

// 'mainnet' like string to relevant GA service root path
static inline struct ext_key* networkToGaService(const char* network)
{
    JADE_ASSERT(network);

    if (!strcmp(TAG_MAINNET, network)) {
        return &MAINNET_SERVICE;
    } else if (!strcmp(TAG_LIQUID, network)) {
        return &LIQUID_SERVICE;
    } else if (isTestNetwork(network)) {
        return &TESTNET_SERVICE;
    } else {
        return NULL;
    }
}

static inline bool ishardened(const uint32_t n)
{
    return (n & BIP32_INITIAL_HARDENED_CHILD) == BIP32_INITIAL_HARDENED_CHILD;
}

static inline uint32_t harden(const uint32_t n) { return n | BIP32_INITIAL_HARDENED_CHILD; }

static inline uint32_t unharden(const uint32_t n) { return n & ~BIP32_INITIAL_HARDENED_CHILD; }

void wallet_init()
{
    JADE_WALLY_VERIFY(bip32_key_from_base58(MAINNET_SERVICE_XPUB, &MAINNET_SERVICE));
    JADE_WALLY_VERIFY(bip32_key_from_base58(TESTNET_SERVICE_XPUB, &TESTNET_SERVICE));
    JADE_WALLY_VERIFY(bip32_key_from_base58(LIQUID_SERVICE_XPUB, &LIQUID_SERVICE));
}

bool bip32_path_as_str(uint32_t parts[], size_t num_parts, char* output, const size_t output_len)
{
    JADE_ASSERT(output);
    JADE_ASSERT(output_len > 16);

    output[0] = 'm';
    output[1] = '\0';

    for (size_t pos = 1, i = 0; i < num_parts; ++i) {
        uint32_t val = parts[i];
        const char* fmt = "/%u";

        if (ishardened(val)) {
            val = unharden(val);
            fmt = "/%u'"; // hardened
        }

        const size_t freespace = output_len - pos;
        const int nchars = snprintf(output + pos, freespace, fmt, val);
        if (nchars < 0 || nchars > freespace) {
            return false;
        }
        pos += nchars;
    }
    return true;
}

// Internal helper to get a derived private key - note 'output' should point to a buffer of size EC_PRIVATE_KEY_LEN
static void wallet_get_privkey(
    const uint32_t* path, const size_t path_size, unsigned char* output, const size_t output_len)
{
    JADE_ASSERT(keychain_get());
    JADE_ASSERT(path);
    JADE_ASSERT(path_size > 0);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len == EC_PRIVATE_KEY_LEN);

    JADE_LOGD("path_size %d", path_size);

    struct ext_key derived;
    SENSITIVE_PUSH(&derived, sizeof(derived));
    JADE_WALLY_VERIFY(bip32_key_from_parent_path(
        &(keychain_get()->xpriv), path, path_size, BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH, &derived));

    memcpy(output, derived.priv_key + 1, output_len);
    SENSITIVE_POP(&derived);
}

// Build a valid/expected green address path from the subact, branch and ptr provided
void wallet_build_receive_path(const uint32_t subaccount, const uint32_t branch, const uint32_t pointer,
    uint32_t* output_path, const size_t output_size, size_t* output_len)
{
    JADE_ASSERT(output_path);
    JADE_ASSERT(output_size >= 4);
    JADE_ASSERT(output_len);

    if (subaccount > 0) {
        output_path[0] = SUBACT_ROOT;
        output_path[1] = harden(subaccount);
        output_path[2] = branch;
        output_path[3] = pointer;
        *output_len = 4;
    } else {
        output_path[0] = branch;
        output_path[1] = pointer;
        *output_len = 2;
    }
}

// Helper to validate the user-path, and fetch the wallet's relevant gait service pubkey
static bool wallet_get_gaservice_key(
    const char* network, const uint32_t* path, const size_t path_size, struct ext_key* gakey)
{
    JADE_ASSERT(keychain_get());
    JADE_ASSERT(network);
    JADE_ASSERT(path);
    JADE_ASSERT(path_size > 0);
    JADE_ASSERT(gakey);

    uint32_t ga_path[35]; // 32 + 3 max
    size_t ga_path_size = 0;

    // We only support the following cases
    if (path_size == 2) {
        // 1.  1/ptr
        if (path[0] != PATH_BRANCH || path[1] >= MAX_PATH_PTR) {
            return false;
        }

        // gapath: 1/<ga service path (32)>/ptr
        ga_path[0] = path[0];
        // skip 1-32
        ga_path[33] = path[1];
        ga_path_size = 34;

    } else if (path_size == 4) {
        // 2.  3'/subact'/1/ptr
        if (path[0] != SUBACT_ROOT || path[1] <= SUBACT_FLOOR || path[1] >= SUBACT_CEILING || path[2] != PATH_BRANCH
            || path[3] >= MAX_PATH_PTR) {
            return false;
        }

        // gapath: 3/<ga service path (32)>/subact/ptr
        ga_path[0] = unharden(path[0]);
        // skip 1-32
        ga_path[33] = unharden(path[1]);
        ga_path[34] = path[3];
        ga_path_size = 35;
    } else {
        return false;
    }

    // GA service path goes in elements 1 - 32 incl.
    const keychain_t* const keychain = keychain_get();
    for (size_t i = 0; i < 32; ++i) {
        ga_path[i + 1] = (keychain->service_path[2 * i] << 8) + keychain->service_path[2 * i + 1];
    }

    // Derive ga account pubkey for the path, except the ptr (so we can log it).
    const struct ext_key* const service = networkToGaService(network);
    if (!service) {
        JADE_LOGE("Unknown network: %s", network);
        return false;
    }
    /*
        // This outputs the parent service xpub to match what the gdk has in its txn data
        struct ext_key garoot;
        JADE_WALLY_VERIFY(bip32_key_from_parent_path(service, ga_path, ga_path_size-1, BIP32_FLAG_KEY_PUBLIC |
       BIP32_FLAG_SKIP_HASH, &garoot));

        // Log this xpub
        char *logbuf;
        JADE_WALLY_VERIFY(bip32_key_to_base58(&garoot, BIP32_FLAG_KEY_PUBLIC, &logbuf));
        JADE_LOGI("service xpub: %s", logbuf);
        wally_free_string(logbuf);

        // Derive final part of the path into the output
        JADE_WALLY_VERIFY(bip32_key_from_parent_path(&garoot, &ga_path[ga_path_size-1], 1, BIP32_FLAG_KEY_PUBLIC |
       BIP32_FLAG_SKIP_HASH, gakey));
     */
    JADE_WALLY_VERIFY(bip32_key_from_parent_path(
        service, ga_path, ga_path_size, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, gakey));
    return true;
}

// Helper to wrap a given script in p2wsh (redeem) and p2sh scripts - note 'output' should point to a buffer of size
// WALLY_SCRIPTPUBKEY_P2SH_LEN
static void wallet_p2sh_p2wsh_scriptpubkey_for_script(
    const unsigned char* script, const size_t script_len, unsigned char* output, const size_t output_len)
{
    JADE_ASSERT(script);
    JADE_ASSERT(script_len > 0);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len == WALLY_SCRIPTPUBKEY_P2SH_LEN);

    unsigned char redeem_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    size_t written = 0;

    // 1. Get redeem script for the passed script
    JADE_WALLY_VERIFY(wally_witness_program_from_bytes(
        script, script_len, WALLY_SCRIPT_SHA256, redeem_script, sizeof(redeem_script), &written));
    JADE_ASSERT(written == WALLY_SCRIPTPUBKEY_P2WSH_LEN);

    // 2. Get p2sh script for the redeem script
    JADE_WALLY_VERIFY(wally_scriptpubkey_p2sh_from_bytes(
        redeem_script, sizeof(redeem_script), WALLY_SCRIPT_HASH160, output, output_len, &written));
    JADE_ASSERT(written == WALLY_SCRIPTPUBKEY_P2SH_LEN);
}

// Helper to build a 2of2/2of3 multisig script
static void wallet_build_multisig(
    const uint8_t* pubkeys, const size_t pubkeys_len, uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(pubkeys_len == 2 * EC_PUBLIC_KEY_LEN || pubkeys_len == 3 * EC_PUBLIC_KEY_LEN); // 2of2 or 2of3
    const size_t nkeys = pubkeys_len / EC_PUBLIC_KEY_LEN;

    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= MSIG_2OFN_SCRIPT_LEN(nkeys)); // Sufficient
    JADE_ASSERT(written);

    // Create 2ofn multisig script
    JADE_WALLY_VERIFY(wally_scriptpubkey_multisig_from_bytes(pubkeys, pubkeys_len, 2, 0, output, output_len, written));
    JADE_ASSERT(*written == MSIG_2OFN_SCRIPT_LEN(nkeys));
}

// Helper to build a 2of2 CSV multisig script
static void wallet_build_csv(const char* network, const uint8_t* pubkeys, const size_t pubkeys_len, const size_t blocks,
    uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(network);
    JADE_ASSERT(pubkeys_len == 2 * EC_PUBLIC_KEY_LEN); // 2of2 only

    JADE_ASSERT(blocks > 0);
    JADE_ASSERT(blocks <= MAX_CSV_BLOCKS_ALLOWED);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= CSV_MAX_SCRIPT_LEN); // Sufficient
    JADE_ASSERT(written);

    // Create 2of2 CSV multisig script (2of3-csv not supported)
    if (isLiquid(network)) {
        // NOTE: we use the original (un-optimised) csv script for liquid
        JADE_WALLY_VERIFY(wally_scriptpubkey_csv_2of2_then_1_from_bytes(
            pubkeys, pubkeys_len, blocks, 0, output, output_len, written));
        JADE_ASSERT(*written >= CSV_MIN_SCRIPT_LEN && *written <= CSV_MAX_SCRIPT_LEN);
    } else {
        // NOTE: we use the 'new-improved!' optimised, miniscript-compatible csv script for btc
        JADE_WALLY_VERIFY(wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt(
            pubkeys, pubkeys_len, blocks, 0, output, output_len, written));
        JADE_ASSERT(*written >= CSV_MIN_SCRIPT_LEN_OPT && *written <= CSV_MAX_SCRIPT_LEN_OPT);
    }
}

// Returns true if we can build a greenaddress p2sh script pubkey from the parameters passed.
// Constructed script pubkey is written into 'output', which must be a buffer of size WALLY_SCRIPTPUBKEY_P2SH_LEN
bool wallet_build_receive_script(const char* network, const char* xpubrecovery, const uint32_t csvBlocks,
    const uint32_t* path, const size_t path_size, unsigned char* output, const size_t output_len)
{
    JADE_ASSERT(keychain_get());

    if (!network || csvBlocks > MAX_CSV_BLOCKS_ALLOWED || !path || path_size == 0 || !output
        || output_len != WALLY_SCRIPTPUBKEY_P2SH_LEN) {
        return false;
    }

    // We do not support 2of3-csv (ie. can't have csv blocks AND a recovery xpub)
    if (csvBlocks > 0 && xpubrecovery) {
        JADE_LOGE("2of3-csv is not supported");
        return false;
    }

    // If csv, ensure above allowed minimum for network
    if (csvBlocks > 0 && csvBlocks < networkToMinAllowedCsvBlocks(network)) {
        JADE_LOGE("csvblocks (%u) too low for network %s", csvBlocks, network);
        return false;
    }

    // The multisig or csv script we generate
    size_t script_size = 0;
    unsigned char script[MSIG_2OFN_SCRIPT_LEN(3)]; // The largest script we might generate

    // The GA and user pubkeys
    unsigned char user_privkey[EC_PRIVATE_KEY_LEN];
    unsigned char pubkeys[3 * EC_PUBLIC_KEY_LEN]; // In case of 2of3
    const size_t num_pubkeys = xpubrecovery ? 3 : 2; // 2of3 if recovery-xpub
    struct ext_key gakey;

    // Get the GA-key for the passed path (if valid)
    if (!wallet_get_gaservice_key(network, path, path_size, &gakey)) {
        JADE_LOGE("Failed to derive valid ga key for path");
        return false;
    }
    memcpy(pubkeys, gakey.pub_key, sizeof(gakey.pub_key));
    JADE_ASSERT(sizeof(gakey.pub_key) == EC_PUBLIC_KEY_LEN);

    // Derive user pubkey from the path
    SENSITIVE_PUSH(user_privkey, sizeof(user_privkey));
    wallet_get_privkey(path, path_size, user_privkey, sizeof(user_privkey));
    JADE_WALLY_VERIFY(wally_ec_public_key_from_private_key(
        user_privkey, sizeof(user_privkey), pubkeys + EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN));
    SENSITIVE_POP(user_privkey);

    // Add recovery key also, if one passed
    if (xpubrecovery) {
        JADE_ASSERT(num_pubkeys == 3);

        struct ext_key key;
        struct ext_key root;

        // xpub includes branch, so only need to derive the final step (ptr)
        const int wret = bip32_key_from_base58(xpubrecovery, &root);
        if (wret != WALLY_OK) {
            JADE_LOGE("Error %d, trying to interpret base58 recovery key '%s'", wret, xpubrecovery);
            return false;
        }

        JADE_WALLY_VERIFY(bip32_key_from_parent_path(
            &root, &path[path_size - 1], 1, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &key));
        memcpy(pubkeys + (2 * EC_PUBLIC_KEY_LEN), key.pub_key, sizeof(key.pub_key));
    }

    // Get 2of2 or 2of3, csv or multisig script, depending on params
    if (csvBlocks > 0) {
        wallet_build_csv(
            network, pubkeys, num_pubkeys * EC_PUBLIC_KEY_LEN, csvBlocks, script, sizeof(script), &script_size);
    } else {
        wallet_build_multisig(pubkeys, num_pubkeys * EC_PUBLIC_KEY_LEN, script, sizeof(script), &script_size);
    }

    // char *logbuf;
    // wally_hex_from_bytes(script, script_size, &logbuf);
    // JADE_LOGI("script generated: %s", logbuf);
    // wally_free_string(logbuf);

    // Get the p2sh/p2wsh script pubkey for the script we have created
    wallet_p2sh_p2wsh_scriptpubkey_for_script(script, script_size, output, output_len);

    // wally_hex_from_bytes(output, output_len, &logbuf);
    // JADE_LOGI("script generated: %s", logbuf);
    // wally_free_string(logbuf);

    return true;
}

// Returns ok if we can build a p2sh script pubkey from the path that matches the one passed
bool wallet_validate_receive_script(const char* network, const char* xpubrecovery, const uint32_t csvBlocks,
    const uint32_t* path, const size_t path_size, const unsigned char* script, const size_t script_len)
{
    if (!network || !path || path_size == 0 || !script || script_len != WALLY_SCRIPTPUBKEY_P2SH_LEN) {
        return false;
    }

    // char *logbuf;
    // wally_hex_from_bytes(script, script_len, &logbuf);
    // JADE_LOGI("wallet_validate_receive_script(), expecting: %s", logbuf);
    // wally_free_string(logbuf);

    unsigned char p2sh_script[WALLY_SCRIPTPUBKEY_P2SH_LEN];
    if (!wallet_build_receive_script(
            network, xpubrecovery, csvBlocks, path, path_size, p2sh_script, sizeof(p2sh_script))) {
        JADE_LOGE("Failed to build receive script");
        return false;
    }

    // Compare generated script to that expected/in the txn
    if (!sodium_memcmp(p2sh_script, script, WALLY_SCRIPTPUBKEY_P2SH_LEN)) {
        const size_t num_pubkeys = xpubrecovery ? 3 : 2; // 2of3 if recovery-xpub
        JADE_LOGI("Receive script validated as a 2of%u %s script", num_pubkeys, csvBlocks > 0 ? "csv" : "multisig");
        return true;
    }

    // Didn't match expected script
    JADE_LOGW("Receive script could not be validated");
    return false;
}

// Function to sign an input hash with a derived key - cannot be the root key, and value must be a sha256 hash.
// Output signature is returned in DER format, with a SIGHASH_ALL postfix - buffer size must be EC_SIGNATURE_DER_MAX_LEN
// + 1.
bool wallet_sign_tx_input_hash(const unsigned char* signature_hash, const size_t signature_hash_len,
    const uint32_t* path, const size_t path_size, unsigned char* output, const size_t output_len, size_t* written)
{
    if (!signature_hash || signature_hash_len != SHA256_LEN || !path || path_size == 0 || !output
        || output_len < EC_SIGNATURE_DER_MAX_LEN + 1 || !written) {
        return false;
    }

    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    unsigned char signature[EC_SIGNATURE_LEN];

    // Derive the child key
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    wallet_get_privkey(path, path_size, privkey, sizeof(privkey));

    // Make the signature in DER format
    JADE_WALLY_VERIFY(wally_ec_sig_from_bytes(privkey, sizeof(privkey), signature_hash, signature_hash_len,
        EC_FLAG_ECDSA | EC_FLAG_GRIND_R, signature, sizeof(signature)));
    SENSITIVE_POP(privkey);
    JADE_WALLY_VERIFY(wally_ec_sig_to_der(signature, sizeof(signature), output, output_len - 1, written));

    // Append the sighash - TODO: make configurable
    output[*written] = WALLY_SIGHASH_ALL & 0xff;
    *written += 1;
    return true;
}

// Function to fetch a hash for a transaction input - output buffer should be of size SHA256_LEN
bool wallet_get_tx_input_hash(struct wally_tx* tx, const size_t index, const bool is_witness, const uint8_t* script,
    const size_t script_len, const uint64_t satoshi, unsigned char* output, const size_t output_len)
{
    if (!tx || !script || script_len == 0 || !output || output_len != SHA256_LEN) {
        return false;
    }

    // Generate the btc signature hash to sign
    const size_t hash_flags = is_witness ? WALLY_TX_FLAG_USE_WITNESS : 0;
    const int wret = wally_tx_get_btc_signature_hash(
        tx, index, script, script_len, satoshi, WALLY_SIGHASH_ALL, hash_flags, output, output_len);
    if (wret != WALLY_OK) {
        JADE_LOGE("Failed to get btc signature hash, error %d", wret);
        return false;
    }
    return true;
}

// Function to fetch a hash for an elements input - output buffer should be of size SHA256_LEN
bool wallet_get_elements_tx_input_hash(struct wally_tx* tx, const size_t index, const bool is_witness,
    const uint8_t* script, const size_t script_len, const unsigned char* satoshi, const size_t satoshi_len,
    unsigned char* output, const size_t output_len)
{
    if (!tx || !script || script_len == 0 || !output || output_len != SHA256_LEN) {
        return false;
    }

    // Generate the elements signature hash to sign
    const size_t hash_flags = is_witness ? WALLY_TX_FLAG_USE_WITNESS : 0;
    const int wret = wally_tx_get_elements_signature_hash(
        tx, index, script, script_len, satoshi, satoshi_len, WALLY_SIGHASH_ALL, hash_flags, output, output_len);
    if (wret != WALLY_OK) {
        JADE_LOGE("Failed to get elements signature hash, error %d", wret);
        return false;
    }
    return true;
}

bool wallet_get_xpub(const char* network, const uint32_t* path, const uint32_t path_len, char** output)
{
    JADE_ASSERT(keychain_get());
    JADE_ASSERT(path_len == 0 || path);

    if (!network || !output) {
        return false;
    }

    // Get the version prefix bytes for the passed network
    const uint32_t version = networkToVersion(network);
    if (!version) {
        JADE_LOGE("Unknown network: %s", network);
        return false;
    }

    struct ext_key derived;
    if (path_len == 0) {
        // Just copy root ext key
        memcpy(&derived, &(keychain_get()->xpriv), sizeof(derived));
    } else {
        // Derive child from root and path - Note: we do NOT pass BIP32_FLAG_SKIP_HASH here
        const int wret
            = bip32_key_from_parent_path(&(keychain_get()->xpriv), path, path_len, BIP32_FLAG_KEY_PRIVATE, &derived);
        if (wret != WALLY_OK) {
            JADE_LOGE("Failed to derive key from path (size %u): %d", path_len, wret);
            return false;
        }
    }

    // Override network/version to yield the correct prefix for the passed network
    derived.version = version;
    JADE_WALLY_VERIFY(bip32_key_to_base58(&derived, BIP32_FLAG_KEY_PUBLIC, output));

    JADE_LOGD("bip32_key_to_base58 %s", *output);
    return true;
}

bool wallet_hmac_with_master_key(
    const unsigned char* data, const uint32_t data_len, unsigned char* output, const uint32_t output_len)
{
    JADE_ASSERT(keychain_get());

    if (!data || data_len == 0 || !output || output_len != HMAC_SHA256_LEN) {
        return false;
    }

    // HMAC with the private key - note we ignore the first byte of the array as it is a prefix to the actual key
    return wally_hmac_sha256(keychain_get()->xpriv.priv_key + 1, sizeof(keychain_get()->xpriv.priv_key) - 1, data,
               data_len, output, output_len)
        == WALLY_OK;
}

bool wallet_get_public_blinding_key(
    const unsigned char* script, const uint32_t script_size, unsigned char* output, const uint32_t output_len)
{
    JADE_ASSERT(keychain_get());

    if (!script || !output || output_len != EC_PUBLIC_KEY_LEN) {
        return false;
    }

    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    const int wret = wally_asset_blinding_key_to_ec_private_key(keychain_get()->master_unblinding_key,
        sizeof(keychain_get()->master_unblinding_key), script, script_size, privkey, sizeof(privkey));
    if (wret != WALLY_OK) {
        JADE_LOGE("Error building asset blinding key for script: %d", wret);
        return false;
    }
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    JADE_WALLY_VERIFY(wally_ec_public_key_from_private_key(privkey, sizeof(privkey), output, output_len));
    SENSITIVE_POP(privkey);

    return true;
}

bool wallet_get_blinding_factor(const unsigned char* hash_prevouts, const size_t hash_len, uint32_t output_index,
    uint8_t type, unsigned char* output, const uint32_t output_len)
{
    JADE_ASSERT(keychain_get());

    if (!hash_prevouts || hash_len != SHA256_LEN || !output || output_len != HMAC_SHA256_LEN
        || (type != ASSET_BLINDING_FACTOR && type != VALUE_BLINDING_FACTOR)) {
        return false;
    }

    unsigned char tx_blinding_key[HMAC_SHA256_LEN];
    JADE_WALLY_VERIFY(
        wally_hmac_sha256(keychain_get()->master_unblinding_key, sizeof(keychain_get()->master_unblinding_key),
            hash_prevouts, SHA256_LEN, tx_blinding_key, sizeof(tx_blinding_key)));

    // msg is either "ABF" or "VBF" with the output index appended at the end.
    // initialize the common part here and then replace vars down
    unsigned char msg[3 + sizeof(uint32_t)] = { type, 'B', 'F', 0x00, 0x00, 0x00, 0x00 };

    // TODO: check endianess of `output_index`
    memcpy(msg + 3, &output_index, sizeof(uint32_t));
    JADE_WALLY_VERIFY(
        wally_hmac_sha256(tx_blinding_key, sizeof(tx_blinding_key), msg, sizeof(msg), output, output_len));

    return true;
}

bool wallet_get_shared_nonce(const unsigned char* script, const uint32_t script_size, const unsigned char* their_pubkey,
    const size_t pubkey_len, unsigned char* output, const uint32_t output_len)
{
    JADE_ASSERT(keychain_get());

    if (!script || !their_pubkey || pubkey_len != EC_PUBLIC_KEY_LEN || !output || output_len != SHA256_LEN) {
        return false;
    }

    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    const int wret = wally_asset_blinding_key_to_ec_private_key(keychain_get()->master_unblinding_key,
        sizeof(keychain_get()->master_unblinding_key), script, script_size, privkey, sizeof(privkey));
    if (wret != WALLY_OK) {
        JADE_LOGE("Error building asset blinding key for script: %d", wret);
        return false;
    }
    const int wret2 = wally_ecdh(their_pubkey, pubkey_len, privkey, sizeof(privkey), output, output_len);
    SENSITIVE_POP(privkey);

    if (wret2 != WALLY_OK) {
        JADE_LOGE("Error building ecdh: %d", wret2);
        return false;
    }

    return true;
}

bool wallet_get_message_hash_hex(const char* message, const size_t bytes_len, char** output)
{
    unsigned char buf[SHA256_LEN];
    size_t written;

    if (!message || !output) {
        return false;
    }

    const int wret = wally_format_bitcoin_message(
        (unsigned char*)message, bytes_len, BITCOIN_MESSAGE_FLAG_HASH, buf, sizeof(buf), &written);
    if (wret != WALLY_OK) {
        JADE_LOGE("Error trying to format btc message '%s': %d", message, wret);
        return false;
    }
    JADE_WALLY_VERIFY(wally_hex_from_bytes(buf, sizeof(buf), output));

    return true;
}

// Function to sign message - output buffer should be of size EC_SIGNATURE_LEN * 2 (which should be ample)
bool wallet_sign_message(const uint32_t* path, const size_t path_size, const char* message, const size_t bytes_len,
    unsigned char* output, const size_t output_len, size_t* written)
{
    unsigned char buf[SHA256_LEN];
    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    unsigned char signature[EC_SIGNATURE_RECOVERABLE_LEN];

    if (!path || !message || bytes_len == 0 || !output || output_len < EC_SIGNATURE_LEN * 2 || !written) {
        return false;
    }

    JADE_LOGD("formatting message %.*s", bytes_len, message);
    const int wret = wally_format_bitcoin_message(
        (unsigned char*)message, bytes_len, BITCOIN_MESSAGE_FLAG_HASH, buf, sizeof(buf), written);
    if (wret != WALLY_OK) {
        JADE_LOGE("Error trying to format btc message '%s': %d", message, wret);
        return false;
    }

    // Derive the child key
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    wallet_get_privkey(path, path_size, privkey, sizeof(privkey));

    // Sign the message
    JADE_WALLY_VERIFY(wally_ec_sig_from_bytes(
        privkey, sizeof(privkey), buf, sizeof(buf), EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE, signature, sizeof(signature)));
    SENSITIVE_POP(privkey);

    mbedtls_base64_encode(output, output_len, written, signature, sizeof(signature));
    JADE_ASSERT(*written < output_len);
    output[*written] = '\0';
    *written += 1;

    return true;
}
