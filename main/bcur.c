#ifndef AMALGAMATED_BUILD
#include "bcur.h"
#include "jade_assert.h"
#include "keychain.h"
#include "qrcode.h"
#include "qrscan.h"
#include "ui.h"
#include "utils/malloc_ext.h"
#include "utils/network.h"
#include "utils/util.h"

#include <cbor.h>
#include <cdecoder.h>
#include <cencoder.h>

// PSBT serialisation functions
bool deserialise_psbt(const uint8_t* bytes, size_t bytes_len, struct wally_psbt** psbt_out);
bool serialise_psbt(const struct wally_psbt* psbt, uint8_t** output, size_t* output_len);

const char BCUR_TYPE_CRYPTO_BIP39[] = "crypto-bip39";
const char BCUR_TYPE_CRYPTO_ACCOUNT[] = "crypto-account";
const char BCUR_TYPE_CRYPTO_HDKEY[] = "crypto-hdkey";
const char BCUR_TYPE_CRYPTO_PSBT[] = "crypto-psbt";
const char BCUR_TYPE_JADE_PIN[] = "jade-pin";
const char BCUR_TYPE_JADE_EPOCH[] = "jade-epoch";
const char BCUR_TYPE_JADE_UPDPS[] = "jade-updps";
const char BCUR_TYPE_JADE_BIP8539_REQUEST[] = "jade-bip8539-request";
const char BCUR_TYPE_JADE_BIP8539_REPLY[] = "jade-bip8539-reply";
const char BCUR_TYPE_BYTES[] = "bytes";

static const char BCUR_PREFIX[] = "ur:";

// Index is QR 'version' (ie size), value is the capacity of
// 'alphanumeric' mode - which is what we use for bcur display
// as restricted to uppercase (assumes BCUR_QR_ECC).
// See: https://www.qrcode.com/en/about/version.html - 'Alphanumeric'
static const uint32_t QR_ALPHANUMERIC_CAPACITY[] = { 0, 25, 47, 77, 114, 154, 195, 224, 279, 335, 395, 468, 535 };

// Index is QR 'version' (ie size), value is the scale factor
// used to get an image as large as sensibly fits the Jade screen.
// NOTE: we can scale up more on larger screens
#if CONFIG_DISPLAY_WIDTH >= 480 && CONFIG_DISPLAY_HEIGHT >= 220
static const uint32_t QR_SCALE_FACTOR[] = { 0, 10, 8, 7, 6, 5, 5, 4, 4, 4, 3, 3, 3 };
#elif CONFIG_DISPLAY_WIDTH >= 320 && CONFIG_DISPLAY_HEIGHT >= 170
static const uint32_t QR_SCALE_FACTOR[] = { 0, 8, 6, 5, 5, 4, 4, 3, 3, 3, 2, 2, 2 };
#else
static const uint32_t QR_SCALE_FACTOR[] = { 0, 6, 5, 4, 4, 3, 3, 2, 2, 2, 2, 2, 2 };
#endif

// NOTE: educated-guesswork/reverse-engineered - pass this value into bcur encoder
// to get a series of text fragments which are within 'capacity' - ie. within the
// capacity of the qr code version we are intending to use.
// max_frag_size = target-capacity - length of the type label - 12 for 'UR:' and
// '/123-123/' - "magic number" 42 (for the cbor+metadata overhead) then halved, as
// it's 2 encoding chars per underlying byte.
// See function 'bcur_check_fragment_sizes()' below for the test of this macro.
#define BCUR_MAX_FRAGMENT_SIZE(capacity, type) ((capacity - strlen(type) - 12 - 42) / 2)

// The ECC mode we use for BCUR QR display
#define BCUR_QR_ECC ECC_LOW

// For every 3 pure data fragments, add one fountain-code fragment.
// This should assist where a frame is missed by the scanner.
// Add a maximum of 100 fountain-code fragments, just for sanity's sake.
#define BCUR_NUM_FRAGMENTS(num_pure_fragments)                                                                         \
    (num_pure_fragments <= 300 ? 4 * num_pure_fragments / 3 : num_pure_fragments + 100)

// Parse bcur bip39 cbor to extract a mnemonic string (space separated words)
// NOTE: only the English wordlist is supported.
bool bcur_parse_bip39(
    const uint8_t* cbor, const size_t cbor_len, char* mnemonic, const size_t mnemonic_len, size_t* written)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(mnemonic_len);
    JADE_INIT_OUT_SIZE(written);

    // Parse cbor
    CborValue value;
    CborParser parser;
    CborError cberr = cbor_parser_init(cbor, cbor_len, CborValidateCompleteData, &parser, &value);
    if (cberr != CborNoError || !cbor_value_is_valid(&value) || !cbor_value_is_container(&value)) {
        return false;
    }

    CborValue mapItem;
    cberr = cbor_value_enter_container(&value, &mapItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&mapItem)) {
        return false;
    }

    int key_res = 0;
    cberr = cbor_value_get_int(&mapItem, &key_res);
    if (cberr != CborNoError || key_res != 1) {
        return false;
    }
    cberr = cbor_value_advance(&mapItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&mapItem) || !cbor_value_is_array(&mapItem)) {
        return false;
    }
    size_t number_of_words = 0;
    cberr = cbor_value_get_array_length(&mapItem, &number_of_words);
    if (cberr != CborNoError || !number_of_words || !cbor_value_is_container(&mapItem)) {
        return false;
    }
    CborValue arrayItem;
    cberr = cbor_value_enter_container(&mapItem, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem) || !cbor_value_is_text_string(&arrayItem)) {
        return false;
    }
    size_t write_pos = 0;
    for (size_t i = 0; i < number_of_words; ++i) {
        if (write_pos) {
            // Add space separator
            mnemonic[write_pos++] = ' ';
        }

        CborValue next;
        size_t tmp_len = mnemonic_len - write_pos;
        cberr = cbor_value_copy_text_string(&arrayItem, mnemonic + write_pos, &tmp_len, &next);
        JADE_ASSERT(cberr == CborNoError);
        write_pos += tmp_len;
        arrayItem = next;
    }
    JADE_ASSERT(cbor_value_at_end(&arrayItem));
    cberr = cbor_value_leave_container(&mapItem, &arrayItem);
    JADE_ASSERT(cberr == CborNoError);

    if (cberr != CborNoError || !cbor_value_is_valid(&mapItem) || !cbor_value_is_integer(&mapItem)) {
        return false;
    }
    cberr = cbor_value_get_int(&mapItem, &key_res);
    if (cberr != CborNoError || key_res != 2) {
        return false;
    }
    cberr = cbor_value_advance(&mapItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&mapItem) || !cbor_value_is_text_string(&mapItem)) {
        return false;
    }

    // NOTE: only the English wordlist is supported.
    bool string_is_en = false;
    cberr = cbor_value_text_string_equals(&mapItem, "en", &string_is_en);

    if (cberr != CborNoError || !string_is_en) {
        return false;
    }
    cberr = cbor_value_advance(&mapItem);
    JADE_ASSERT(cberr == CborNoError && cbor_value_at_end(&mapItem));

    cberr = cbor_value_leave_container(&value, &mapItem);
    JADE_ASSERT(cberr == CborNoError);

    mnemonic[write_pos++] = '\0';
    *written = write_pos;

    return true;
}

// Parse bcur bip39 data to extract a mnemonic string (space separated words)
// NOTE: only the English wordlist is supported.
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
bool bcur_parse_bip39_wrapper(
    const char* bcur, const size_t bcur_len, char* mnemonic, const size_t mnemonic_len, size_t* written)
{
    JADE_ASSERT(bcur);
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(mnemonic_len);
    JADE_INIT_OUT_SIZE(written);

    // Decode bcur string
    bool ret = false;
    uint8_t decoder[URDECODER_SIZE];
    urcreate_placement_decoder(decoder, sizeof(decoder));
    if (!urreceive_part_decoder(decoder, bcur) || !uris_success_decoder(decoder)) {
        JADE_LOGW("Unable to decode bcur bip39 string from single part");
        goto cleanup;
    }

    // Read the result
    char const* type = NULL;
    uint8_t* result = NULL;
    size_t result_len = 0;
    urresult_ur_decoder(decoder, &result, &result_len, &type);
    if (!type || !result || !result_len || strcasecmp(BCUR_TYPE_CRYPTO_BIP39, type)) {
        JADE_LOGW("Unable to decode bcur bip39 string to expected type %s", BCUR_TYPE_CRYPTO_BIP39);
        goto cleanup;
    }

    // Decode the cbor
    if (!bcur_parse_bip39(result, result_len, mnemonic, mnemonic_len, written)) {
        JADE_LOGW("Failed to parse bcur bip39 cbor message");
        goto cleanup;
    }

    // All good
    ret = true;

cleanup:
    urfree_placement_decoder(decoder);
    return ret;
}

// Parse the bcur cbor for raw undifferentiated bytes (bytes) - just bytes.
// NOTE: this returns a pointer to the byte buffer allocated in the existing cbor input
// *AND NOT* a freshly allocated or copied range.
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
bool bcur_parse_bytes(const uint8_t* cbor, size_t cbor_len, const uint8_t** bytes, size_t* bytes_len)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);
    JADE_INIT_OUT_PPTR(bytes);
    JADE_INIT_OUT_SIZE(bytes_len);

    // Parse cbor
    CborValue value;
    CborParser parser;
    const CborError cberr = cbor_parser_init(cbor, cbor_len, CborValidateCompleteData, &parser, &value);
    if (cberr != CborNoError || !cbor_value_is_valid(&value)) {
        return false;
    }

    rpc_get_raw_bytes_ptr(&value, bytes, bytes_len);
    return *bytes && *bytes_len;
}

// Parse the bcur cbor for a PSBT (crypto-psbt) - just bytes
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
bool bcur_parse_psbt(const uint8_t* cbor, const size_t cbor_len, struct wally_psbt** psbt_out)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);
    JADE_INIT_OUT_PPTR(psbt_out);

    // Parse cbor, get pointer to existing bytes
    const uint8_t* data = NULL;
    size_t data_len = 0;
    if (!bcur_parse_bytes(cbor, cbor_len, &data, &data_len)) {
        return false;
    }

    // Convert to wally psbt structure
    if (!deserialise_psbt(data, data_len, psbt_out)) {
        JADE_LOGW("wally_psbt_from_bytes() failed for %u bytes", data_len);
        return false;
    }

    return true;
}

// Helper to initiate parsing a Jade message
bool bcur_parse_jade_message(const uint8_t* cbor, size_t cbor_len, CborParser* parser, CborValue* root,
    const char* expected_method, CborValue* params)
{
    JADE_ASSERT(cbor);
    JADE_ASSERT(cbor_len);
    JADE_ASSERT(parser);
    JADE_ASSERT(root);
    // expected_method is optional
    // params is optional

    // Parse cbor
    CborError cberr = cbor_parser_init(cbor, cbor_len, CborValidateCompleteData, parser, root);
    if (cberr != CborNoError || !cbor_value_is_valid(root) || !cbor_value_is_map(root)) {
        JADE_LOGE("Failed to parse bcur cbor message");
        return false;
    }

    // Caller can optionally pass the expected method name - if so this is verified.
    if (expected_method) {
        size_t method_len = 0;
        const char* method = NULL;
        rpc_get_method(root, &method, &method_len);
        if (!method || !method_len || strncmp(expected_method, method, method_len)
            || method_len != strlen(expected_method)) {
            JADE_LOGE("Failed to read expected method name");
            return false;
        }
    }

    // If caller also wants params, the params map must be present
    // If caller hasn't asked for params, they are allowed to not be present.
    if (params) {
        cberr = cbor_value_map_find_value(root, CBOR_RPC_TAG_PARAMS, params);
        if (cberr != CborNoError || !cbor_value_is_valid(params) || cbor_value_get_type(params) == CborInvalidType
            || !cbor_value_is_map(params)) {
            JADE_LOGE("Failed to fetch parameters map");
            return false;
        }
    }
    return true;
}

// Encode a txn psbt as a bcur cbor 'bytes' - just bytes
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
bool bcur_build_cbor_bytes(const uint8_t* data, const size_t data_len, uint8_t** output, size_t* output_len)
{
    JADE_ASSERT(data);
    JADE_ASSERT(data_len);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);

    // Format as simple cbor message containing only bytes
    const size_t buflen = data_len + 8; // sufficient for cbor overhead
    uint8_t* buf = JADE_MALLOC_PREFER_SPIRAM(buflen);
    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, buf, buflen, 0);
    const CborError cberr = cbor_encode_byte_string(&root_encoder, data, data_len);
    JADE_ASSERT(cberr == CborNoError);

    const size_t cbor_len = cbor_encoder_get_buffer_size(&root_encoder, buf);
    JADE_ASSERT(cbor_len > data_len && cbor_len <= buflen);

    // Copy cbor buffer to output
    *output = buf;
    *output_len = cbor_len;
    return true;
}

// Encode a txn psbt as a bcur cbor 'crypto-psbt' - just bytes
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
bool bcur_build_cbor_crypto_psbt(const struct wally_psbt* psbt, uint8_t** output, size_t* output_len)
{
    JADE_ASSERT(psbt);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);

    // Serialise updated psbt
    uint8_t* psbt_bytes_out = NULL;
    size_t psbt_len_out = 0;
    if (!serialise_psbt(psbt, &psbt_bytes_out, &psbt_len_out)) {
        return false;
    }

    // Format as simple cbor message
    const bool ret = bcur_build_cbor_bytes(psbt_bytes_out, psbt_len_out, output, output_len);
    free(psbt_bytes_out);
    return ret;
}

static void encode_script_variant_tag(CborEncoder* encoder, const script_variant_t script_variant)
{
    JADE_ASSERT(encoder);

    CborError cberr = CborNoError;
    switch (script_variant) {
    // Singlesig
    case P2PKH:
        cberr = cbor_encode_tag(encoder, 403);
        JADE_ASSERT(cberr == CborNoError);
        break;
    case P2WPKH:
        cberr = cbor_encode_tag(encoder, 404);
        JADE_ASSERT(cberr == CborNoError);
        break;
    case P2WPKH_P2SH:
        cberr = cbor_encode_tag(encoder, 400);
        JADE_ASSERT(cberr == CborNoError);
        cberr = cbor_encode_tag(encoder, 404);
        JADE_ASSERT(cberr == CborNoError);
        break;
    // Generic multisig
    case MULTI_P2SH:
        cberr = cbor_encode_tag(encoder, 400);
        JADE_ASSERT(cberr == CborNoError);
        break;
    case MULTI_P2WSH:
        cberr = cbor_encode_tag(encoder, 401);
        JADE_ASSERT(cberr == CborNoError);
        break;
    case MULTI_P2WSH_P2SH:
        cberr = cbor_encode_tag(encoder, 400);
        JADE_ASSERT(cberr == CborNoError);
        cberr = cbor_encode_tag(encoder, 401);
        JADE_ASSERT(cberr == CborNoError);
        break;
    // Taproot
    case P2TR:
        cberr = cbor_encode_tag(encoder, 409);
        JADE_ASSERT(cberr == CborNoError);
        break;
    default:
        JADE_ASSERT_MSG(false, "Unhandled script variant");
    }
}

static void encode_hdkey(CborEncoder* encoder, const uint32_t fingerprint, const uint32_t* path, const size_t path_len)
{
    JADE_ASSERT(encoder);
    JADE_ASSERT(fingerprint);
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);

    // We will include the 'useinfo' section if testnet
    const bool testnet = keychain_get_network_type_restriction() == NETWORK_TYPE_TEST;

    // The hdkey for the passed path
    struct ext_key hdkey;
    const bool ret = wallet_get_hdkey(path, path_len, BIP32_FLAG_KEY_PUBLIC, &hdkey);
    JADE_ASSERT(ret);
    JADE_ASSERT(hdkey.depth == path_len);

    // hdkey
    CborEncoder key_map_encoder;
    CborError cberr = cbor_encoder_create_map(encoder, &key_map_encoder, testnet ? 5 : 4);
    JADE_ASSERT(cberr == CborNoError);

    // pubkey
    cberr = cbor_encode_uint(&key_map_encoder, 3);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_byte_string(&key_map_encoder, hdkey.pub_key, sizeof(hdkey.pub_key));
    JADE_ASSERT(cberr == CborNoError);

    // chaincode
    cberr = cbor_encode_uint(&key_map_encoder, 4);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_byte_string(&key_map_encoder, hdkey.chain_code, sizeof(hdkey.chain_code));
    JADE_ASSERT(cberr == CborNoError);

    // use-info (to indicate testnet wallet)
    if (testnet) {
        cberr = cbor_encode_uint(&key_map_encoder, 5);
        JADE_ASSERT(cberr == CborNoError);
        {
            cbor_encode_tag(&key_map_encoder, 305);
            CborEncoder use_info_map_encoder;
            cberr = cbor_encoder_create_map(&key_map_encoder, &use_info_map_encoder, 2);
            JADE_ASSERT(cberr == CborNoError);

            // type - btc
            cberr = cbor_encode_uint(&use_info_map_encoder, 1);
            JADE_ASSERT(cberr == CborNoError);
            cberr = cbor_encode_uint(&use_info_map_encoder, 0);
            JADE_ASSERT(cberr == CborNoError);

            // network
            cberr = cbor_encode_uint(&use_info_map_encoder, 2);
            JADE_ASSERT(cberr == CborNoError);
            cberr = cbor_encode_uint(&use_info_map_encoder, testnet ? 1 : 0);
            JADE_ASSERT(cberr == CborNoError);

            // Close the use-info map
            cberr = cbor_encoder_close_container(&key_map_encoder, &use_info_map_encoder);
            JADE_ASSERT(cberr == CborNoError);
        }
    }

    // origin information
    cberr = cbor_encode_uint(&key_map_encoder, 6);
    JADE_ASSERT(cberr == CborNoError);
    {
        // key path
        cbor_encode_tag(&key_map_encoder, 304);
        CborEncoder key_path_map_encoder;
        cberr = cbor_encoder_create_map(&key_map_encoder, &key_path_map_encoder, 3);
        JADE_ASSERT(cberr == CborNoError);

        {
            cberr = cbor_encode_uint(&key_path_map_encoder, 1);
            JADE_ASSERT(cberr == CborNoError);
            CborEncoder key_path_array_encoder;
            cberr = cbor_encoder_create_array(&key_path_map_encoder, &key_path_array_encoder, 2 * path_len);
            JADE_ASSERT(cberr == CborNoError);
            for (int i = 0; i < path_len; ++i) {
                cberr = cbor_encode_uint(&key_path_array_encoder, unharden(path[i]));
                JADE_ASSERT(cberr == CborNoError);
                cberr = cbor_encode_boolean(&key_path_array_encoder, ishardened(path[i]));
                JADE_ASSERT(cberr == CborNoError);
            }

            // Close the path array
            cberr = cbor_encoder_close_container(&key_path_map_encoder, &key_path_array_encoder);
            JADE_ASSERT(cberr == CborNoError);
        }

        // origin fingerprint - ie. master key fingerprint
        cberr = cbor_encode_uint(&key_path_map_encoder, 2);
        JADE_ASSERT(cberr == CborNoError);
        cberr = cbor_encode_uint(&key_path_map_encoder, fingerprint);
        JADE_ASSERT(cberr == CborNoError);

        // path length / depth
        cberr = cbor_encode_uint(&key_path_map_encoder, 3);
        JADE_ASSERT(cberr == CborNoError);
        cberr = cbor_encode_uint(&key_path_map_encoder, hdkey.depth);
        JADE_ASSERT(cberr == CborNoError);

        // Close the path map
        cberr = cbor_encoder_close_container(&key_map_encoder, &key_path_map_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }

    // parent fingerprint - immediate parent
    uint32_t parentfp = 0;
    uint32_to_be(*(uint32_t*)hdkey.parent160, (uint8_t*)(&parentfp));

    cberr = cbor_encode_uint(&key_map_encoder, 8);
    JADE_ASSERT(cberr == CborNoError);
    cberr = cbor_encode_uint(&key_map_encoder, parentfp);
    JADE_ASSERT(cberr == CborNoError);

    // Close the key map
    cberr = cbor_encoder_close_container(encoder, &key_map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

// Encode an wallet path/key as a bcur cbor 'crypto-hdkey'
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md
void bcur_build_cbor_crypto_hdkey(
    const uint32_t* path, const size_t path_len, uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= 128);
    JADE_INIT_OUT_SIZE(written);

    // Wallet fingerprint
    uint8_t fingerprint_bytes[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(fingerprint_bytes, sizeof(fingerprint_bytes));
    uint32_t fingerprint = 0;
    uint32_to_be(*(uint32_t*)fingerprint_bytes, (uint8_t*)(&fingerprint));

    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, output, output_len, 0);

    // hdkey
    encode_hdkey(&root_encoder, fingerprint, path, path_len);

    *written = cbor_encoder_get_buffer_size(&root_encoder, output);
    JADE_ASSERT(*written);
}

// Encode an wallet path/key as a bcur cbor 'crypto-account'
// See: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md
void bcur_build_cbor_crypto_account(const script_variant_t script_variant, const uint32_t* path, const size_t path_len,
    uint8_t* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(path);
    JADE_ASSERT(path_len);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= 128);
    JADE_INIT_OUT_SIZE(written);

    // Green multisig-shield not supported
    JADE_ASSERT(!is_greenaddress(script_variant));

    // Wallet fingerprint
    uint8_t fingerprint_bytes[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(fingerprint_bytes, sizeof(fingerprint_bytes));
    uint32_t fingerprint = 0;
    uint32_to_be(*(uint32_t*)fingerprint_bytes, (uint8_t*)(&fingerprint));

    CborEncoder root_encoder;
    cbor_encoder_init(&root_encoder, output, output_len, 0);
    {
        // Fingerprint and list of output descriptors
        CborEncoder root_map_encoder;
        CborError cberr = cbor_encoder_create_map(&root_encoder, &root_map_encoder, 2);
        JADE_ASSERT(cberr == CborNoError);

        // fingerprint - immediate parent, or root parent of the path given ?
        cberr = cbor_encode_uint(&root_map_encoder, 1);
        JADE_ASSERT(cberr == CborNoError);
        cberr = cbor_encode_uint(&root_map_encoder, fingerprint);
        JADE_ASSERT(cberr == CborNoError);

        cberr = cbor_encode_uint(&root_map_encoder, 2);
        JADE_ASSERT(cberr == CborNoError);
        {
            // Just one output descriptor
            CborEncoder key_array_encoder;
            cberr = cbor_encoder_create_array(&root_map_encoder, &key_array_encoder, 1);
            JADE_ASSERT(cberr == CborNoError);

            // script-type tag(s)
            encode_script_variant_tag(&key_array_encoder, script_variant);

            // Single hdkey
            cbor_encode_tag(&key_array_encoder, 303);
            encode_hdkey(&key_array_encoder, fingerprint, path, path_len);

            // Close the array
            cberr = cbor_encoder_close_container(&root_map_encoder, &key_array_encoder);
            JADE_ASSERT(cberr == CborNoError);
        }

        // Close the root map
        cberr = cbor_encoder_close_container(&root_encoder, &root_map_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }
    *written = cbor_encoder_get_buffer_size(&root_encoder, output);
    JADE_ASSERT(*written);
}

// Support scanning a bc-ur qr-code - single-frame or animated/multi-frame.
// Adds a scanned bc-ur qr the bcur decoder - only returns true when the decoder is complete.
// ie. collates multiple frames until the entire bc-ur data is complete.
// If the qr-code scanned is not a bc-ur part, return success immediately.
// Updates associated progress-bar as parts are scanned.
static bool collect_any_bcur(qr_data_t* qr_data)
{
    JADE_ASSERT(qr_data);
    JADE_ASSERT(qr_data->len);
    JADE_ASSERT(qr_data->ctx);
    JADE_ASSERT(qr_data->progress_bar);
    JADE_ASSERT(qr_data->data[qr_data->len] == '\0');

    if (qr_data->len < sizeof(BCUR_PREFIX)
        || strncasecmp((const char*)qr_data->data, BCUR_PREFIX, sizeof(BCUR_PREFIX) - 1)) {
        // Not bc-ur - return immediately
        update_progress_bar(qr_data->progress_bar, 1, 1);
        return true;
    }

    // The scanned data looks like a bcur code or fragment, add it to the bcur decoder
    // and return true only when the bcur decoder says the message is complete.
    const bool processed_part = urreceive_part_decoder(qr_data->ctx, (const char*)qr_data->data);

    // On hard failure, reset the decoder
    if (uris_failure_decoder(qr_data->ctx)) {
        JADE_LOGE("Failure to scan bcur data - resetting the decoder");
        urfree_placement_decoder(qr_data->ctx);
        urcreate_placement_decoder(qr_data->ctx, URDECODER_SIZE);
        return false;
    }

    // Update associated progress bar - be a bit defensive here
    const bool decoded = uris_success_decoder(qr_data->ctx);
    const size_t nreceived = urreceived_parts_count_decoder(qr_data->ctx);
    if (processed_part && nreceived) {
        // NOTE: can only call 'expected' once we have received at least one part
        const size_t nexpected = urexpected_part_count_decoder(qr_data->ctx);

        // If fully decoded show full bar - but if not fully decoded
        // don't show a full bar - pause at 'almost done' if required.
        if (decoded) {
            update_progress_bar(qr_data->progress_bar, nexpected, nexpected);
        } else if (nreceived < nexpected) {
            update_progress_bar(qr_data->progress_bar, nexpected, nreceived);
        }
        // else, appear to have all pieces but not fully decoded ...
        // just leave progress bar showing whatever 'almost done' level.
    }

    // Return true if complete
    return decoded;
}

// Scan a QR code that may be a BC-UR code/fragment - ie. single-frame or animated/multi-frame.
// Returns true if a complete (ie. potentially multi-frame) bc-ur code is scanned, or if a single
// non-BC-UR frame is scanned successfully.
// If BC-UR, the complete scanned payload and its BC-UR 'type' are returned.
// NOTE: output is expected to be a valid CBOR message, although this is not validated.
// If not BC-UR, the scanned payload is returned with a type of NULL.
// In either case the caller takes ownership, and must free the output data bytes and any type string.
// Returns false if scanning fails or is abandoned - in which case there is nothing to free.
bool bcur_scan_qr(
    const char* prompt_text, char** output_type, uint8_t** output, size_t* output_len, const char* help_url)
{
    // prompt_text is optional
    JADE_INIT_OUT_PPTR(output_type);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);

    uint8_t urdecoder[URDECODER_SIZE];
    urcreate_placement_decoder(urdecoder, sizeof(urdecoder));
    progress_bar_t progress_bar = {};
    qr_data_t qr_data = { .len = 0, .is_valid = collect_any_bcur, .ctx = urdecoder, .progress_bar = &progress_bar };

    // Scan qr code using the bcur decoder to collate multiple frames if required
    if (!jade_camera_scan_qr(&qr_data, prompt_text, QR_GUIDE_SHOW, help_url)) {
        // User exited without completing scanning
        urfree_placement_decoder(urdecoder);
        return false;
    }

    // Copy output into output params - caller takes ownership
    if (uris_success_decoder(urdecoder)) {
        // bcur message scanned - extract from decoder and return the payload
        uint8_t* result = NULL;
        size_t result_len = 0;
        const char* result_type = NULL;
        urresult_ur_decoder(urdecoder, &result, &result_len, &result_type);
        JADE_ASSERT(result);
        JADE_ASSERT(result_len);
        JADE_ASSERT(result_type);

        // Copy payload and bc-ur type
        *output = JADE_MALLOC_PREFER_SPIRAM(result_len);
        memcpy(*output, result, result_len);
        *output_len = result_len;
        *output_type = strdup(result_type);
    } else {
        // Not a bc-ur code - copy straight payload and append a nul-terminator.
        // Leave bc-ur type as NULL to indicate data was not a bc-ur payload.
        *output = JADE_MALLOC(qr_data.len + 1);
        memcpy(*output, qr_data.data, qr_data.len);
        (*output)[qr_data.len] = '\0';
        *output_len = qr_data.len;
        *output_type = NULL;
    }

    // Free the decoder and return true (as we scanned data successfully)
    urfree_placement_decoder(urdecoder);
    return true;
}

// Encodes the passed payload into a set of one or more BC-UR fragments with the given 'type'.
// These are then rendered as a set of QR codes of the passed version/size.
// NOTE: input is expected to be a valid CBOR message, although this is not validated
// Caller takes ownership of the icons returned.
// NOTE Only supports qr-versions from 4 to 12  (4, 6 and 12 fit nicely on a v1 Jade screen, and
// 4, 6 and 9 on the larger v2 screen (with greater scaling)).
void bcur_create_qr_icons(const uint8_t* payload, const size_t len, const char* bcur_type, const uint8_t qr_version,
    Icon** icons, size_t* num_icons)
{
    JADE_ASSERT(payload);
    JADE_ASSERT(len);
    JADE_ASSERT(bcur_type);
    JADE_ASSERT(qr_version >= 4);
    JADE_ASSERT(qr_version <= 12);
    JADE_INIT_OUT_PPTR(icons);
    JADE_INIT_OUT_SIZE(num_icons);

    // The 'bcur_max_fragment_size' passed into the encoder is the number of payload bytes to aim to put into
    // each fragment. The final fragment is much larger as also contains metadata/checksums, is then encoded
    // into ascii using 'codewords' (which is two characters per byte), and then has a text header - but it is
    // this final size that must respect the QR code capacity. The 'BCUR_MAX_FRAGMENT_SIZE()' macro should yield
    // the maximum amount of payload data for each fragment, and there are asserts to check - but if tweaking the
    // qrcode version we need to check the passed 'capacity' produces fragments <= 'qrcode_alphanumeric_capacity'
    // as the qrcode.c library is not very robust if too much data is passed to 'qrcode_initText()'.
    const uint16_t qrcode_alphanumeric_capacity = QR_ALPHANUMERIC_CAPACITY[qr_version];
    const uint16_t bcur_max_fragment_size = BCUR_MAX_FRAGMENT_SIZE(qrcode_alphanumeric_capacity, bcur_type);
    JADE_ASSERT(bcur_max_fragment_size < qrcode_alphanumeric_capacity); // didn't 'under'flow

    // Encode the message as bc-ur
    JADE_LOGI("BC-UR encoding payload length %u as type %s", len, bcur_type);
    JADE_LOGI("Targetting qr-code version %u, capacity %u (alphanumeric mode), using max fragment size %u", qr_version,
        qrcode_alphanumeric_capacity, bcur_max_fragment_size);
    uint8_t encoder[URENCODER_SIZE];
    urcreate_placement_encoder(encoder, sizeof(encoder), bcur_type, payload, len, bcur_max_fragment_size, 0, 8);
    const size_t min_num_fragments = urseqlen_encoder(encoder); // the number of 'pure' data fragments
    const size_t num_fragments = BCUR_NUM_FRAGMENTS(min_num_fragments); // add some fountain-code fragments
    JADE_ASSERT(num_fragments >= min_num_fragments);
    JADE_LOGI("Encoded payload length %u as %u pure fragments and %u fountain-code fragments", len, min_num_fragments,
        num_fragments - min_num_fragments);

    // Underlying qrcode data/work area - opaque
    uint8_t* qrbuffer = JADE_MALLOC(qrcode_getBufferSize(qr_version));

    // Convert to 'num_fragments' qr-code icons
    const bool force_uppercase = true; // fetch bcur fragment as uppercase to conform to 'alphanumeric' qr mode
    Icon* const qr_icons = JADE_MALLOC(num_fragments * sizeof(Icon));
    for (int ifrag = 0; ifrag < num_fragments; ++ifrag) {
        char* fragment = NULL;
        urnext_part_encoder(encoder, force_uppercase, &fragment);
        const size_t fragment_len = strlen(fragment);
        JADE_LOGI("Fragment %u, making qr-code icon with data (length: %u): %s", ifrag, fragment_len, fragment);

        // We assert here that our BCUR_MAX_FRAGMENT_SIZE() macro did not come up
        // with a size that was too large for the qr-code target.
        JADE_ASSERT(fragment_len <= qrcode_alphanumeric_capacity);

        QRCode qrcode;
        const int qret = qrcode_initText(&qrcode, qrbuffer, qr_version, BCUR_QR_ECC, fragment);
        JADE_ASSERT(qret == 0);
        urfree_encoded_encoder(fragment);

        // Convert fragment to Icon
        qrcode_toIcon(&qrcode, qr_icons + ifrag, QR_SCALE_FACTOR[qr_version]);
    }
    JADE_ASSERT(uris_complete_encoder(encoder));

    free(qrbuffer);
    urfree_placement_encoder(encoder);

    // Return the created icons
    *icons = qr_icons;
    *num_icons = num_fragments;
}

#ifdef CONFIG_DEBUG_MODE
// NOTE: iterative test for the BCUR_MAX_FRAGMENT_SIZE() macro which yields the input
// 'max fragment size' (of payload data) to produce output bcur-encoded fragments close to
// (but not more than!) the desired qr-code capacity.
// NOTE: takes a while to run - qemu recommended! (~5mins on my laptop, on qemu)
bool bcur_check_fragment_sizes(void)
{
    // Test various versions, with various message types, and various payload lengths
    bool overflowed = false;
    const uint8_t versions[] = { 4, 6, 12 }; // the versions & ur-types of interest
    const char* types[] = { BCUR_TYPE_CRYPTO_PSBT, BCUR_TYPE_CRYPTO_ACCOUNT, BCUR_TYPE_CRYPTO_HDKEY, BCUR_TYPE_JADE_PIN,
        BCUR_TYPE_JADE_BIP8539_REPLY };
    uint8_t payload[4096];

    for (uint8_t iver = 0; iver < sizeof(versions); ++iver) {
        const uint8_t ver = versions[iver];
        const size_t capacity = QR_ALPHANUMERIC_CAPACITY[ver];
        JADE_LOGI("Testing version %u, capacity %u", ver, capacity);

        for (uint8_t itype = 0; itype < 4; ++itype) {
            const char* type = types[itype];
            const size_t maxlen = BCUR_MAX_FRAGMENT_SIZE(capacity, type);
            JADE_ASSERT(maxlen < capacity);
            JADE_LOGI("Testing type %s, maxlen %u", type, maxlen);
            size_t max = 0;

            for (size_t len = maxlen - 8; len < sizeof(payload); ++len) {
                uint8_t encoder[URENCODER_SIZE];
                urcreate_placement_encoder(encoder, sizeof(encoder), type, payload, len, maxlen, 0, 8);

                char* fragment = NULL;
                urnext_part_encoder(encoder, true, &fragment);
                JADE_ASSERT(fragment);
                const size_t fraglen = strlen(fragment);
                if (fraglen + 4 > capacity) {
                    // In truth fraglen == capacity is valid, but later parts (and of larger payloads)
                    // are larger as the ascii sequence numbers get longer - eg. '/1-6/' vs. '367-826'
                    // so we as we only test the first part we'll insist on a margin to allow for this.
                    JADE_LOGE("len %u -> %u", len, fraglen);
                    overflowed = true;
                }
                if (fraglen > max) {
                    max = fraglen;
                }
                urfree_encoded_encoder(fragment);
                urfree_placement_encoder(encoder);
            }
            JADE_LOGI("max: %u (of target/limit %u)", max, capacity);
        }
    }
    return !overflowed;
}
#endif
#endif // AMALGAMATED_BUILD
