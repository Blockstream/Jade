#include "bcur.h"
#include "jade_assert.h"
#include "qrcode.h"
#include "qrscan.h"
#include "ui.h"
#include "utils/malloc_ext.h"

#include <cbor.h>
#include <cdecoder.h>
#include <cencoder.h>

const char BCUR_TYPE_CRYPTO_ACCOUNT[] = "crypto-account";
const char BCUR_TYPE_CRYPTO_HDKEY[] = "crypto-hdkey";
const char BCUR_TYPE_CRYPTO_PSBT[] = "crypto-psbt";
const char BCUR_TYPE_JADE_PIN[] = "jade-pin";

static const char BCUR_PREFIX[] = "ur:";

// Index is QR 'version' (ie size), value is the capacity of
// 'alphanumeric' mode - which is what we use for bcur display
// as restricted to uppercase (assumes BCUR_QR_ECC).
// See: https://www.qrcode.com/en/about/version.html - 'Alphanumeric'
static const uint32_t QR_ALPHANUMERIC_CAPACITY[] = { 0, 25, 47, 77, 114, 154, 195, 224, 279, 335, 395, 468, 535 };

// Index is QR 'version' (ie size), value is the scale factor
// used to get an image as large as sensibly fits the Jade screen.
static const uint32_t QR_SCALE_FACTOR[] = { 0, 6, 5, 4, 4, 3, 3, 3, 2, 2, 2, 2, 2 };

// NOTE: educated-guesswork/reverse-engineered - pass this value into bcur decoder
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
static bool parse_bcur_bip39_cbor(
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
bool bcur_parse_bip39(
    const char* bcur, const size_t bcur_len, char* mnemonic, const size_t mnemonic_len, size_t* written)
{
    JADE_ASSERT(bcur);
    JADE_ASSERT(mnemonic);
    JADE_ASSERT(mnemonic_len);
    JADE_INIT_OUT_SIZE(written);

    // Expected type for bip39 mnemonic
    const char expected_type[] = "crypto-bip39";

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
    if (!type || !result || !result_len || strcasecmp(expected_type, type)) {
        JADE_LOGW("Unable to decode bcur bip39 string to expected type %s", expected_type);
        goto cleanup;
    }

    // Decode the cbor
    if (!parse_bcur_bip39_cbor(result, result_len, mnemonic, mnemonic_len, written)) {
        JADE_LOGW("Failed to parse bcur bip39 cbor message");
        goto cleanup;
    }

    // All good
    ret = true;

cleanup:
    urfree_placement_decoder(decoder);
    return ret;
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
bool bcur_scan_qr(const char* prompt_text, char** output_type, uint8_t** output, size_t* output_len)
{
    JADE_ASSERT(prompt_text);
    JADE_INIT_OUT_PPTR(output_type);
    JADE_INIT_OUT_PPTR(output);
    JADE_INIT_OUT_SIZE(output_len);

    uint8_t urdecoder[URDECODER_SIZE];
    urcreate_placement_decoder(urdecoder, sizeof(urdecoder));
    progress_bar_t progress_bar = { .progress_bar = NULL };
    qr_data_t qr_data = { .len = 0, .is_valid = collect_any_bcur, .ctx = urdecoder, .progress_bar = &progress_bar };

    // Scan qr code using the bcur decoder to collate multiple frames if required
    if (!jade_camera_scan_qr(&qr_data, prompt_text)) {
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
// NOTE Only supports qr-versions from 4 to 12  (4, 6 and 12 fit nicely on a Jade screen).
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
    const char* types[]
        = { BCUR_TYPE_CRYPTO_PSBT, BCUR_TYPE_CRYPTO_ACCOUNT, BCUR_TYPE_CRYPTO_HDKEY, BCUR_TYPE_JADE_PIN };
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
