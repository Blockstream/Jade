#include "wallet.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "sensitive.h"
#include "utils/network.h"

#include <stdio.h>
#include <string.h>

#include <wally_address.h>
#include <wally_anti_exfil.h>
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

// multisig script length for n keys (m-of-n)
#define MULTISIG_SCRIPT_LEN(n) (3 + (n * (EC_PUBLIC_KEY_LEN + 1)))

// Supported script variants (as well as the default green multisig/csv)
#define VARIANT_P2PKH "pkh(k)"
#define VARIANT_P2WPKH "wpkh(k)"
#define VARIANT_P2WPKH_P2SH "sh(wpkh(k))"

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

static inline void value_to_be(uint32_t val, unsigned char* buffer)
{
    buffer[0] = (val >> 24) & 0xFF;
    buffer[1] = (val >> 16) & 0xFF;
    buffer[2] = (val >> 8) & 0xFF;
    buffer[3] = val & 0xFF;
}

void wallet_init()
{
    JADE_WALLY_VERIFY(bip32_key_from_base58(MAINNET_SERVICE_XPUB, &MAINNET_SERVICE));
    JADE_WALLY_VERIFY(bip32_key_from_base58(TESTNET_SERVICE_XPUB, &TESTNET_SERVICE));
    JADE_WALLY_VERIFY(bip32_key_from_base58(LIQUID_SERVICE_XPUB, &LIQUID_SERVICE));
}

bool bip32_path_as_str(const uint32_t parts[], size_t num_parts, char* output, const size_t output_len)
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

static inline size_t script_length_for_variant(const script_variant_t script_variant)
{
    switch (script_variant) {
    case P2PKH:
        return WALLY_SCRIPTPUBKEY_P2PKH_LEN;
    case P2WPKH:
        return WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    default:
        return WALLY_SCRIPTPUBKEY_P2SH_LEN;
    }
}

// Map a script-variant string into the corresponding enum value
bool get_script_variant(const char* variant, const size_t variant_len, script_variant_t* output)
{
    if (variant == NULL || variant_len == 0) {
        // Default to Green multisig/csv
        *output = GREEN;
    } else if (strcmp(VARIANT_P2PKH, variant) == 0) {
        *output = P2PKH;
    } else if (strcmp(VARIANT_P2WPKH, variant) == 0) {
        *output = P2WPKH;
    } else if (strcmp(VARIANT_P2WPKH_P2SH, variant) == 0) {
        *output = P2WPKH_P2SH;
    } else {
        // Unrecognised
        JADE_LOGW("Unrecognised script variant: %s", variant);
        return false;
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

// Helper to wrap a given script or pubkey in p2wsh/p2wpkh (redeem) and p2sh scripts - note 'output' should point to a
// buffer at least WALLY_SCRIPTPUBKEY_P2SH_LEN in length. bytes can be either a pubkey (p2wpkh) or a script (p2wsh) and
// flags should then be either WALLY_SCRIPT_HASH160 (for p2wpkh) or WALLY_SCRIPT_SHA256 (for p2wsh)
static void wallet_p2sh_p2wsh_scriptpubkey_for_bytes(const unsigned char* bytes, const size_t bytes_len, uint32_t flags,
    unsigned char* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(bytes_len > 0);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= WALLY_SCRIPTPUBKEY_P2SH_LEN);
    JADE_ASSERT(flags == WALLY_SCRIPT_SHA256 || flags == WALLY_SCRIPT_HASH160);
    JADE_ASSERT(written);

    unsigned char redeem_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient for p2wsh and p2wpkh

    // 1. Get redeem script for the passed script
    JADE_WALLY_VERIFY(
        wally_witness_program_from_bytes(bytes, bytes_len, flags, redeem_script, sizeof(redeem_script), written));
    const size_t expected_written
        = flags == WALLY_SCRIPT_SHA256 ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    JADE_ASSERT(*written == expected_written);

    // 2. Get p2sh script for the redeem script
    JADE_WALLY_VERIFY(wally_scriptpubkey_p2sh_from_bytes(
        redeem_script, expected_written, WALLY_SCRIPT_HASH160, output, output_len, written));
    JADE_ASSERT(*written == WALLY_SCRIPTPUBKEY_P2SH_LEN);
}

// Helper to build an M-of-N multisig script
static void wallet_build_multisig(const size_t threshold, const uint8_t* pubkeys, const size_t pubkeys_len,
    uint8_t* output, const size_t output_len, size_t* written)
{
    const size_t nkeys = pubkeys_len / EC_PUBLIC_KEY_LEN;
    JADE_ASSERT(nkeys * EC_PUBLIC_KEY_LEN == pubkeys_len);

    JADE_ASSERT(nkeys > 1);
    JADE_ASSERT(threshold > 0);
    JADE_ASSERT(threshold <= nkeys);

    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= MULTISIG_SCRIPT_LEN(nkeys)); // Sufficient
    JADE_ASSERT(written);

    // Create m-of-n multisig script
    JADE_LOGI("Generating %uof%u multisig script", threshold, nkeys);
    JADE_WALLY_VERIFY(
        wally_scriptpubkey_multisig_from_bytes(pubkeys, pubkeys_len, threshold, 0, output, output_len, written));
    JADE_ASSERT(*written == MULTISIG_SCRIPT_LEN(nkeys));
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
    if (isLiquidNetwork(network)) {
        // NOTE: we use the original (un-optimised) csv script for liquid
        JADE_LOGI("Generating liquid csv script");
        JADE_WALLY_VERIFY(wally_scriptpubkey_csv_2of2_then_1_from_bytes(
            pubkeys, pubkeys_len, blocks, 0, output, output_len, written));
        JADE_ASSERT(*written >= CSV_MIN_SCRIPT_LEN && *written <= CSV_MAX_SCRIPT_LEN);
    } else {
        // NOTE: we use the 'new-improved!' optimised, miniscript-compatible csv script for btc
        JADE_LOGI("Generating optimised csv script");
        JADE_WALLY_VERIFY(wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt(
            pubkeys, pubkeys_len, blocks, 0, output, output_len, written));
        JADE_ASSERT(*written >= CSV_MIN_SCRIPT_LEN_OPT && *written <= CSV_MAX_SCRIPT_LEN_OPT);
    }
}

// Helper to build a green-address script - 2of2 or 2of3 multisig, or a 2of2 csv
static bool wallet_build_ga_script(const char* network, const char* xpubrecovery, const uint32_t csvBlocks,
    const uint32_t* path, const size_t path_size, unsigned char* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(network);
    JADE_ASSERT(written);
    JADE_ASSERT(output_len >= WALLY_SCRIPTPUBKEY_P2SH_LEN);
    JADE_ASSERT(keychain_get());

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
    unsigned char script[MULTISIG_SCRIPT_LEN(3)]; // The largest script we might generate

    // The GA and user pubkeys
    unsigned char user_privkey[EC_PRIVATE_KEY_LEN];
    unsigned char pubkeys[3 * EC_PUBLIC_KEY_LEN]; // In case of 2of3
    const size_t num_pubkeys = xpubrecovery ? 3 : 2; // 2of3 if recovery-xpub
    unsigned char* next_pubkey = pubkeys;

    // Get the GA key if this is a green-multisig script
    struct ext_key gakey;

    // Get the GA-key for the passed path (if valid)
    if (!wallet_get_gaservice_key(network, path, path_size, &gakey)) {
        JADE_LOGE("Failed to derive valid ga key for path");
        return false;
    }
    memcpy(next_pubkey, gakey.pub_key, sizeof(gakey.pub_key));
    JADE_ASSERT(sizeof(gakey.pub_key) == EC_PUBLIC_KEY_LEN);
    next_pubkey += sizeof(gakey.pub_key);

    // Derive user pubkey from the path
    SENSITIVE_PUSH(user_privkey, sizeof(user_privkey));
    wallet_get_privkey(path, path_size, user_privkey, sizeof(user_privkey));
    JADE_WALLY_VERIFY(
        wally_ec_public_key_from_private_key(user_privkey, sizeof(user_privkey), next_pubkey, EC_PUBLIC_KEY_LEN));
    SENSITIVE_POP(user_privkey);
    next_pubkey += EC_PUBLIC_KEY_LEN;

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
        memcpy(next_pubkey, key.pub_key, sizeof(key.pub_key));
    }

    // Get 2of2 or 2of3, csv or multisig script, depending on params
    if (csvBlocks > 0) {
        wallet_build_csv(
            network, pubkeys, num_pubkeys * EC_PUBLIC_KEY_LEN, csvBlocks, script, sizeof(script), &script_size);
    } else {
        wallet_build_multisig(2, pubkeys, num_pubkeys * EC_PUBLIC_KEY_LEN, script, sizeof(script), &script_size);
    }

    // Get the p2sh/p2wsh script-pubkey for the script we have created
    wallet_p2sh_p2wsh_scriptpubkey_for_bytes(script, script_size, WALLY_SCRIPT_SHA256, output, output_len, written);
    return true;
}

// Helper to build a single-sig script - legacy-p2pkh, native segwit p2wpkh, or a p2sh-wrapped p2wpkh
static bool wallet_build_singlesig_script(const char* network, const script_variant_t script_variant,
    const uint32_t* path, const size_t path_size, unsigned char* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(network);
    JADE_ASSERT(written);
    JADE_ASSERT(output_len >= WALLY_SCRIPTPUBKEY_P2PKH_LEN);
    JADE_ASSERT(keychain_get());

    // The user pubkeys
    unsigned char user_privkey[EC_PRIVATE_KEY_LEN];
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];

    // Derive user pubkey from the path
    SENSITIVE_PUSH(user_privkey, sizeof(user_privkey));
    wallet_get_privkey(path, path_size, user_privkey, sizeof(user_privkey));
    JADE_WALLY_VERIFY(wally_ec_public_key_from_private_key(user_privkey, sizeof(user_privkey), pubkey, sizeof(pubkey)));
    SENSITIVE_POP(user_privkey);

    if (script_variant == P2WPKH_P2SH) {
        // Get the p2sh/p2wsh script-pubkey for the passed pubkey
        JADE_LOGI("Generating singlesig p2wpkh_p2sh script");
        wallet_p2sh_p2wsh_scriptpubkey_for_bytes(
            pubkey, sizeof(pubkey), WALLY_SCRIPT_HASH160, output, output_len, written);
    } else if (script_variant == P2WPKH) {
        // Get a redeem script for the passed pubkey
        JADE_LOGI("Generating singlesig p2wpkh script");
        JADE_WALLY_VERIFY(wally_witness_program_from_bytes(
            pubkey, sizeof(pubkey), WALLY_SCRIPT_HASH160, output, output_len, written));
    } else if (script_variant == P2PKH) {
        // Get a legacy p2pkh script-pubkey for the passed pubkey
        JADE_LOGI("Generating singlesig p2pkh script");
        JADE_WALLY_VERIFY(wally_scriptpubkey_p2pkh_from_bytes(
            pubkey, sizeof(pubkey), WALLY_SCRIPT_HASH160, output, output_len, written));
    } else {
        JADE_LOGE("Unrecognised script variant: %u", script_variant);
        return false;
    }

    JADE_ASSERT(*written == script_length_for_variant(script_variant));
    return true;
}

// Returns true if we can build a script pubkey from the parameters passed.
// Constructed script pubkey is written into 'output', which must be a buffer of size WALLY_SCRIPTPUBKEY_P2WSH_LEN.
bool wallet_build_receive_script(const char* network, const script_variant_t script_variant, const char* xpubrecovery,
    const uint32_t csvBlocks, const uint32_t* path, const size_t path_size, unsigned char* output,
    const size_t output_len, size_t* written)
{
    JADE_ASSERT(written);
    JADE_ASSERT(keychain_get());

    if (!network || csvBlocks > MAX_CSV_BLOCKS_ALLOWED || !path || path_size == 0 || !output
        || output_len < WALLY_SCRIPTPUBKEY_P2WSH_LEN) {
        return false;
    }

    if (script_variant == GREEN) {
        // GA multisig/csv
        return wallet_build_ga_script(network, xpubrecovery, csvBlocks, path, path_size, output, output_len, written);
    } else {
        // Multisig is only supported for green atm
        if (xpubrecovery) {
            JADE_LOGE("Incompatible options variant and recovery xpub");
            return false;
        }

        // csv does not apply to non-green either
        if (csvBlocks) {
            JADE_LOGE("Incompatible options variant and csv blocks");
            return false;
        }

        return wallet_build_singlesig_script(network, script_variant, path, path_size, output, output_len, written);
    }
}

// Returns ok if we can build a p2sh script pubkey from the path that matches the one passed
bool wallet_validate_receive_script(const char* network, const script_variant_t script_variant,
    const char* xpubrecovery, const uint32_t csvBlocks, const uint32_t* path, const size_t path_size,
    const unsigned char* script, const size_t script_len)
{
    if (!network || !path || path_size == 0 || !script || script_len != script_length_for_variant(script_variant)) {
        return false;
    }

    size_t generated_script_len = 0;
    unsigned char generated_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN]; // Sufficient for all scripts
    if (!wallet_build_receive_script(network, script_variant, xpubrecovery, csvBlocks, path, path_size,
            generated_script, sizeof(generated_script), &generated_script_len)) {
        JADE_LOGE("Failed to build receive script");
        return false;
    }

    // Compare generated script to that expected/in the txn
    if (generated_script_len == script_len && !sodium_memcmp(generated_script, script, script_len)) {
        JADE_LOGI("Receive script validated");
        return true;
    }

    // Didn't match expected script
    JADE_LOGW("Receive script could not be validated");
    return false;
}

// Function to compute an anti-exfil signer commitment with a derived key for a given
// signature hash (SHA256_LEN) and host commitment (WALLY_HOST_COMMITMENT_LEN).
// Output must be of size WALLY_S2C_OPENING_LEN.
bool wallet_get_signer_commitment(const uint8_t* signature_hash, const size_t signature_hash_len, const uint32_t* path,
    const size_t path_size, const uint8_t* commitment, const size_t commitment_len, uint8_t* output,
    const size_t output_len)
{
    if (!signature_hash || signature_hash_len != SHA256_LEN || !path || path_size == 0 || !commitment
        || commitment_len != WALLY_HOST_COMMITMENT_LEN || !output || output_len != WALLY_S2C_OPENING_LEN) {
        return false;
    }

    // Derive the child key
    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    wallet_get_privkey(path, path_size, privkey, sizeof(privkey));

    // Generate the signer commitment nonce
    const int wret = wally_ae_signer_commit_from_bytes(privkey, sizeof(privkey), signature_hash, signature_hash_len,
        commitment, commitment_len, EC_FLAG_ECDSA, output, output_len);
    SENSITIVE_POP(privkey);

    if (wret != WALLY_OK) {
        JADE_LOGE("Failed to get signer commitment nonce, error %d", wret);
        return false;
    }
    return true;
}

// Function to sign an input hash with a derived key - cannot be the root key, and value must be a sha256 hash.
// If 'ae_host_entropy' is passed it is used to generate an 'anti-exfil' signature, otherwise a standard EC signature
// (ie. using rfc6979) is created.  The output signature is returned in DER format, with a SIGHASH_ALL postfix.
// Output buffer size must be EC_SIGNATURE_DER_MAX_LEN.
// NOTE: the standard EC signature will 'grind-r' to produce a 'low-r' signature, the anti-exfil case
// cannot (as the entropy is provided explicitly).
bool wallet_sign_tx_input_hash(const uint8_t* signature_hash, const size_t signature_hash_len, const uint32_t* path,
    const size_t path_size, const uint8_t* ae_host_entropy, const size_t ae_host_entropy_len, uint8_t* output,
    const size_t output_len, size_t* written)
{
    if (!signature_hash || signature_hash_len != SHA256_LEN || !path || path_size == 0 || !output
        || output_len < EC_SIGNATURE_DER_MAX_LEN + 1 || !written) {
        return false;
    }
    if ((!ae_host_entropy && ae_host_entropy_len > 0)
        || (ae_host_entropy && ae_host_entropy_len != WALLY_S2C_DATA_LEN)) {
        return false;
    }

    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    unsigned char signature[EC_SIGNATURE_LEN];

    // Derive the child key
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    wallet_get_privkey(path, path_size, privkey, sizeof(privkey));

    // Generate signature as appropriate
    int wret;
    if (ae_host_entropy) {
        // Anti-Exfil signature
        wret = wally_ae_sig_from_bytes(privkey, sizeof(privkey), signature_hash, signature_hash_len, ae_host_entropy,
            ae_host_entropy_len, EC_FLAG_ECDSA, signature, sizeof(signature));
    } else {
        // Standard EC signature
        wret = wally_ec_sig_from_bytes(privkey, sizeof(privkey), signature_hash, signature_hash_len,
            EC_FLAG_ECDSA | EC_FLAG_GRIND_R, signature, sizeof(signature));
    }
    SENSITIVE_POP(privkey);

    if (wret != WALLY_OK) {
        JADE_LOGE("Failed to make signature, error %d", wret);
        return false;
    }

    // Make the signature in DER format
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
    SENSITIVE_PUSH(&derived, sizeof(derived));

    if (path_len == 0) {
        // Just copy root ext key
        memcpy(&derived, &(keychain_get()->xpriv), sizeof(derived));
    } else {
        // Derive child from root and path - Note: we do NOT pass BIP32_FLAG_SKIP_HASH here
        const int wret
            = bip32_key_from_parent_path(&(keychain_get()->xpriv), path, path_len, BIP32_FLAG_KEY_PRIVATE, &derived);
        if (wret != WALLY_OK) {
            SENSITIVE_POP(&derived);
            JADE_LOGE("Failed to derive key from path (size %u): %d", path_len, wret);
            return false;
        }
    }

    // Override network/version to yield the correct prefix for the passed network
    derived.version = version;
    JADE_WALLY_VERIFY(bip32_key_to_base58(&derived, BIP32_FLAG_KEY_PUBLIC, output));
    SENSITIVE_POP(&derived);

    JADE_LOGD("bip32_key_to_base58: %s", *output);
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

    // NOTE: 'master_unblinding_key' is stored here as the full output of hmac512, when according to slip-0077
    // the master unblinding key is only the second half of that - ie. 256 bits
    // 'wally_asset_blinding_key_to_ec_private_key()' takes this into account...
    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    const int wret = wally_asset_blinding_key_to_ec_private_key(keychain_get()->master_unblinding_key,
        sizeof(keychain_get()->master_unblinding_key), script, script_size, privkey, sizeof(privkey));
    if (wret != WALLY_OK) {
        SENSITIVE_POP(privkey);
        JADE_LOGE("Error building asset blinding key for script: %d", wret);
        return false;
    }
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

    // NOTE: 'master_unblinding_key' is stored here as the full output of hmac512, when according to slip-0077
    // the master unblinding key is only the second half of that - ie. 256 bits
    // So we only use the relevant slice of the data for this derivation (consistent with ledger).
    JADE_ASSERT(sizeof(keychain_get()->master_unblinding_key) == HMAC_SHA512_LEN);
    unsigned char tx_blinding_key[HMAC_SHA256_LEN];
    JADE_WALLY_VERIFY(wally_hmac_sha256(keychain_get()->master_unblinding_key + HMAC_SHA256_LEN, HMAC_SHA256_LEN,
        hash_prevouts, SHA256_LEN, tx_blinding_key, sizeof(tx_blinding_key)));

    // msg is either "ABF" or "VBF" with the output index appended at the end.
    // initialize the common part here and then replace vars down
    unsigned char msg[3 + sizeof(uint32_t)] = { type, 'B', 'F', 0x00, 0x00, 0x00, 0x00 };

    value_to_be(output_index, msg + 3);
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

    // NOTE: 'master_unblinding_key' is stored here as the full output of hmac512, when according to slip-0077
    // the master unblinding key is only the second half of that - ie. 256 bits
    // 'wally_asset_blinding_key_to_ec_private_key()' takes this into account...
    const int wret = wally_asset_blinding_key_to_ec_private_key(keychain_get()->master_unblinding_key,
        sizeof(keychain_get()->master_unblinding_key), script, script_size, privkey, sizeof(privkey));
    if (wret != WALLY_OK) {
        SENSITIVE_POP(privkey);
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

bool wallet_get_message_hash(const uint8_t* bytes, const size_t bytes_len, uint8_t* output, const size_t output_len)
{
    if (!bytes || bytes_len == 0 || !output || output_len != SHA256_LEN) {
        return false;
    }

    size_t written = 0;
    const int wret
        = wally_format_bitcoin_message(bytes, bytes_len, BITCOIN_MESSAGE_FLAG_HASH, output, output_len, &written);
    if (wret != WALLY_OK) {
        JADE_LOGE("Error trying to format btc message: %d", wret);
        return false;
    }
    return true;
}

// Function to sign a message hash with a derived key - cannot be the root key, and value must be a sha256 hash.
// If 'ae_host_entropy' is passed it is used to generate an 'anti-exfil' signature, otherwise a standard EC signature
// (ie. using rfc6979) is created.  The output signature is returned base64 encoded.
// The output buffer should be of size at least EC_SIGNATURE_LEN * 2 (which should be ample).
bool wallet_sign_message_hash(const uint8_t* signature_hash, const size_t signature_hash_len, const uint32_t* path,
    const size_t path_size, const uint8_t* ae_host_entropy, const size_t ae_host_entropy_len, uint8_t* output,
    const size_t output_len, size_t* written)
{
    if (!path || !signature_hash || signature_hash_len != SHA256_LEN || !output || output_len < EC_SIGNATURE_LEN * 2
        || !written) {
        return false;
    }
    if ((!ae_host_entropy && ae_host_entropy_len > 0)
        || (ae_host_entropy && ae_host_entropy_len != WALLY_S2C_DATA_LEN)) {
        return false;
    }

    // Derive the child key
    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(privkey, sizeof(privkey));
    wallet_get_privkey(path, path_size, privkey, sizeof(privkey));

    // Generate signature as appropriate
    int wret;
    uint8_t signature[EC_SIGNATURE_RECOVERABLE_LEN];
    size_t signature_len = 0;
    if (ae_host_entropy) {
        // Anti-Exfil signature
        signature_len = EC_SIGNATURE_LEN;
        wret = wally_ae_sig_from_bytes(privkey, sizeof(privkey), signature_hash, signature_hash_len, ae_host_entropy,
            ae_host_entropy_len, EC_FLAG_ECDSA, signature, signature_len);
    } else {
        // Standard EC recoverable signature
        signature_len = EC_SIGNATURE_RECOVERABLE_LEN;
        wret = wally_ec_sig_from_bytes(privkey, sizeof(privkey), signature_hash, signature_hash_len,
            EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE, signature, signature_len);
    }
    SENSITIVE_POP(privkey);

    if (wret != WALLY_OK) {
        JADE_LOGE("Failed to make signature, error %d", wret);
        return false;
    }
    // Base64 encode
    mbedtls_base64_encode(output, output_len, written, signature, signature_len);
    JADE_ASSERT(*written < output_len);
    output[*written] = '\0';
    *written += 1;

    return true;
}
