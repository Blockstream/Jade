#include "bcur.h"
#include "jade_assert.h"

#include <cbor.h>
#include <cdecoder.h>

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
