#include <stdlib.h>
#include <string.h>

#include "bcur.h"
#include "jade_assert.h"
#include "selfcheck.h"
#include "utils/malloc_ext.h"

#include <ur_decoder.h>
#include <ur_encoder.h>
#include <wally_core.h>

// Defined in main/bcur.c (debug builds).  Verifies the BCUR_MAX_FRAGMENT_SIZE()
// macro against the real qr-code alphanumeric capacities.
bool bcur_check_fragment_sizes(void);

#define FREE_DECODER_AND_FAIL(d)                                                                                       \
    do {                                                                                                               \
        ur_decoder_free(d);                                                                                            \
        FAIL();                                                                                                        \
    } while (false)

#define FREE_ENCODER_AND_FAIL(e)                                                                                       \
    do {                                                                                                               \
        ur_encoder_free(e);                                                                                            \
        FAIL();                                                                                                        \
    } while (false)

#define FREE_ENCODED_PARTS(p)                                                                                          \
    do {                                                                                                               \
        for (int i = 0; i < sizeof(p) / sizeof(p[0]); ++i) {                                                           \
            free(p[i]);                                                                                                \
        }                                                                                                              \
    } while (false)

static bool test_bcur_decode_encode(void)
{
    const size_t encoder_max_fragment_len = 142; // relates to the size of the string fragments below
    const char qr_part1of2[]
        = "UR:CRYPTO-PSBT/1-2/"
          "LPADAOCFADCWCYGEFGCHDWHDMNHKADCSJOJKIDJYZMADAEJPAOAEAEAEADECKIPKNBTODLATWTEOPRECNTCLGYDKOTMOGMECVSTELKEHVEHE"
          "KEAYGRPLRHTNLTADAEAEAEAEZMZMZMZMAOTIATAEAEAEAEAEAECHPTBBPMWNSSLUBTBEPRZMFWIMPTCPIOAXECQDWEAMLUKILTPKDRAEAEAE"
          "AEAEAECMAEBBKPLFPKADUYWKGAMNRDIHGYZTMTTTFXRSGSZTGEWTAEAEAEAEAEADADCTBNEOAEAEAEAEAEAECMAEBBMTDESNLBPSCP";
    const char qr_part2of2[]
        = "UR:CRYPTO-PSBT/2-2/"
          "LPAOAOCFADCWCYGEFGCHDWHDMNSBWEJSNDVWKESSMDZCZCOLFPSPPMCEBGYKYTCPAMAXLDMDHSREMNCTEHLFMTBNBNGLLPRYGOTKFPCPFEVT"
          "FRBZVASNJYNDRHHHLRAALRTSCSAEAEAEAEGHAEAELAAEAEAELAAEAEAELAAEAEAEAEBWAEAEAEAEAECPAOAOCMLPLOTYFHEHCYKEJNGDFNJT"
          "IHKPYAEMKPVENLGSDIECNLRYWSIAFDJZNDNTLDAHCSAEAEAEAEGHAEAELAAEAEAELAAEAEAELAADAEAEAEBAAEAEAEAEAEDTSOTETL";
    const char expected_type[] = "crypto-psbt";
    const char hex_expected[]
        = "59011870736274ff0100720200000001357daaa0ce2f07f033b2359d215124a3925235e8d38c31e45f7c084baeb9da870100000000ff"
          "ffffff02d00700000000000017a914adf1c48b0d10b2ff426aa922670335b3ed068b7d87aa2a0000000000001600147582aa01dbf449"
          "8eba6551fc96d143bf4cfc4af0000000000001011f0c330000000000001600149628cbed719be57cc495fdfda641c8ad1c12f5f92206"
          "03899561b58e1f3182960c0c4e85bd55cf412245e03b15e6cd749bb95c840484d7180000000054000080000000800000008000000000"
          "130000000000220202168588d43f311a7c6d503c6e6575f83775e4994c273599bdef63486c9b9d890518000000005400008000000080"
          "00000080010000000e00000000";

    size_t payload_len = 0;
    uint8_t payload[sizeof(hex_expected) / 2];
    const int wret = wally_hex_to_bytes(hex_expected, payload, sizeof(payload), &payload_len);
    JADE_ASSERT(wret == WALLY_OK);
    JADE_ASSERT(payload_len == sizeof(payload));

    // 1. Try decoder
    {
        // Check decoder with a message of 2 'pure' fragments
        ur_decoder_t* const decoder = ur_decoder_new();
        JADE_ASSERT(decoder);
        if (ur_decoder_get_state(decoder) != UR_DECODER_PROCESSING) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 0) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        // NOTE: Can't call ur_decoder_expected_part_count() until first part processed

        // send first qr - should be processed, but NOT complete yet
        if (ur_decoder_receive_part(decoder, qr_part1of2) != UR_DECODER_PROCESSING) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 1) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_expected_part_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // send first qr again - should be ignored/harmless, still NOT complete
        if (ur_decoder_receive_part(decoder, qr_part1of2) != UR_DECODER_PROCESSING) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 1) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_expected_part_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // send second qr - should now be complete
        if (ur_decoder_receive_part(decoder, qr_part2of2) != UR_DECODER_OK) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_expected_part_count(decoder) != 2) {
            FREE_DECODER_AND_FAIL(decoder);
        }

        // read the result - borrowed from the decoder, freed with it
        const ur_result_t* const result = ur_decoder_get_result(decoder);
        JADE_ASSERT(result);
        JADE_ASSERT(result->type);
        JADE_ASSERT(result->cbor_len);
        JADE_ASSERT(result->cbor_data);
        if (strncmp(expected_type, result->type, strlen(expected_type))) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (result->cbor_len != payload_len || memcmp(result->cbor_data, payload, result->cbor_len)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        ur_decoder_free(decoder);
    }

    // 2. Try encoder
    {
        // If we encode the data, the first two parts should match the original payloads
        // ie. the 'pure' fragments (ie. the actual data split into two and encoded)
        ur_encoder_t* const encoder
            = ur_encoder_new(expected_type, payload, payload_len, encoder_max_fragment_len, 0, 10);
        JADE_ASSERT(encoder);
        char* parts[3] = { NULL, NULL, NULL };
        if (!ur_encoder_next_part(encoder, &parts[0]) || !parts[0]
            || strncmp(parts[0], qr_part1of2, strlen(qr_part1of2))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        if (ur_encoder_is_complete(encoder)) {
            // Should NOT be complete yet
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }

        if (!ur_encoder_next_part(encoder, &parts[1]) || !parts[1]
            || strncmp(parts[1], qr_part2of2, strlen(qr_part2of2))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        if (!ur_encoder_is_complete(encoder)) {
            // Should now be complete
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }

        // We can continue to generate additional parts - these are fountain-code fragments
        // which can stand in for any missed fragments.  NOTE: the sequence-numbers appear 'overflowed'.
        if (!ur_encoder_next_part(encoder, &parts[2]) || !parts[2]
            || strncmp(parts[2], "UR:CRYPTO-PSBT/3-2/", strlen("UR:CRYPTO-PSBT/3-2/"))) {
            FREE_ENCODED_PARTS(parts);
            FREE_ENCODER_AND_FAIL(encoder);
        }
        ur_encoder_free(encoder);

        // Check fountain encoding / redundancy with fresh decoders - incl. getting a 'later' part first
        // Check all 2-of-3 combinations - any 2 distinct parts should be sufficient.
        for (size_t i = 0; i < 3; ++i) {
            // Fountain code parts are blended together or with other 'pure' data parts to generate
            // additional/missing data parts.  If we receive a fountain-code part first it can't generate
            // any data parts on its own - so does not initially bump the 'received parts' count.
            // (It is cached in the decoder, and may generate one or more parts later when further parts
            // are received - so 'received parts' can jump by more than 1 when a subsequent message is received.)
            const size_t initial_expected_received = i == 2 ? 0 : 1;

            for (size_t j = 0; j < 3; ++j) {
                ur_decoder_t* const decoder = ur_decoder_new();
                JADE_ASSERT(decoder);

                // Present first part - should be processed, but NOT complete yet
                if (ur_decoder_receive_part(decoder, parts[i]) != UR_DECODER_PROCESSING) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_processed_parts_count(decoder) != 1) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_expected_part_count(decoder) != 2) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_received_parts_count(decoder) != initial_expected_received) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }

                // Present second part
                const ur_decoder_state_t state = ur_decoder_receive_part(decoder, parts[j]);
                if (ur_decoder_state_is_error(state)) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                // NOTE: a duplicate part is deduped before it is counted, so
                // 'processed' remains 1 if the same part is presented twice
                if (ur_decoder_processed_parts_count(decoder) != (i != j ? 2 : 1)) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }
                if (ur_decoder_expected_part_count(decoder) != 2) {
                    FREE_ENCODED_PARTS(parts);
                    FREE_DECODER_AND_FAIL(decoder);
                }

                // If any two different parts are presented, this should be
                // sufficient to reconstruct the complete message.
                // NOTE: a fountain part followed by a 'pure' part will mean the
                // 'received' count 0 after the fountain part, then jumps to 2 when
                // the 'pure' data part is received (and can be combined with the fountain
                // part to generate the missing data part).
                if (i != j) {
                    if (ur_decoder_received_parts_count(decoder) != 2) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (state != UR_DECODER_OK) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }

                    // Check payload is as expected - result borrowed from the decoder
                    const ur_result_t* const result = ur_decoder_get_result(decoder);
                    JADE_ASSERT(result);
                    JADE_ASSERT(result->type);
                    JADE_ASSERT(result->cbor_len);
                    JADE_ASSERT(result->cbor_data);
                    if (strncmp(expected_type, result->type, strlen(expected_type))) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (result->cbor_len != payload_len || memcmp(result->cbor_data, payload, result->cbor_len)) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                } else {
                    // Same part received twice - does not increment 'received_parts'
                    if (ur_decoder_received_parts_count(decoder) != initial_expected_received) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                    if (state != UR_DECODER_PROCESSING) {
                        FREE_ENCODED_PARTS(parts);
                        FREE_DECODER_AND_FAIL(decoder);
                    }
                }
                ur_decoder_free(decoder);
            }
        }
        FREE_ENCODED_PARTS(parts);
    }
    return true;
}

static bool test_bcur_decode_bad_cases(void)
{
    const char* cases[] = { // Simple cases
        "this is not even a ur message at all!", "ur:has prefix but still not a ur message?",
        "ur:crypto-bip39/looks like a bip39 message but bad payload encoding",
        "ur:bytes/1-3/multipart bad payload encoding, it would seem", "ur:bytes/1,2/multipart bad sequence numbers",

        // Singlepart messages can have any payload, so long as it is bytewords encoded

        // Multipart messages - encoded payload should be wrapped in a known cbor envelope with
        // metadata for the fountain encoder  (the actual user-payload inside that can be anything)
        "ur:bytes/1-3/jyisinjkcxinjkcxjtjljycxiaidjljpclstwpfdmk", // encoded payload not cbor
        "ur:bytes/1-3/" // encoded payload is cbor, but not the expected fields
        "oeieiahsjkihksceiaidjljpcxiajljtjyihjtjycxjtjljycxhsjkcxihksjoihiajyihiejlihksjoihiajyihiecxjpihjkkpjzjyioinio"
        "jtjljpihiedklbcfpt",

        // This one was actually produced by one of the 3rd-party sw wallet apps - wrong on so many levels!
        "UR:BYTES/3OF3/V6Z4WY8JQT9JZPXQCQWNV8HRWL2FKYJ9HDPHN6HZSYPC3K284N3S0V96L4/"
        "8LF6C3NEX24337544L49GQQQSQQQQQYQQQQQPQQPQQQQQQQQQQQQQH47708"
    };
    const size_t ncases = sizeof(cases) / sizeof(cases[0]);

    // Various bad cases - test the decoder ignores them
    for (size_t i = 0; i < ncases; ++i) {
        ur_decoder_t* const decoder = ur_decoder_new();
        JADE_ASSERT(decoder);

        // Present first part - should be rejected with a transient (non-terminal)
        // error, and all counts of 'parts seen' should remain zero.
        const ur_decoder_state_t state = ur_decoder_receive_part(decoder, cases[i]);
        if (!ur_decoder_state_is_error(state)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_state_is_terminal(state)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_processed_parts_count(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        if (ur_decoder_received_parts_count(decoder)) {
            FREE_DECODER_AND_FAIL(decoder);
        }
        ur_decoder_free(decoder);
    }
    return true;
}

// Test we can render a small sequence of bcur qr-code icons
// Cover all handled versions - use more data for larger versions.
// ('ver * ver * 8' seems to give 6 icons, which seems reasonable)
static bool test_bcur_icons(void)
{
    const uint8_t payload[12 * 12 * 8] = { 0 };
    for (uint8_t ver = 4; ver <= 12; ++ver) {
        const size_t payload_len = ver * ver * 8;
        Icon* icons = NULL;
        size_t num_icons = 0;
        bcur_create_qr_icons(payload, payload_len, "test-type", ver, &icons, &num_icons);
        if (!icons || !num_icons) {
            FAIL();
        }
        for (size_t i = 0; i < num_icons; ++i) {
            JADE_ASSERT(icons[i].data);
            free(icons[i].data);
        }
        free(icons);
    }
    return true;
}

// Test we can render a sequence of up to 1000 bcur fragments
static bool test_bcur_large_payload_many_icons(void)
{
    const int qr_version = 4; // smallest supported
    const int payload_len = 22 * 1024; // 22k, should result ~1000 fragments
    uint8_t* payload = JADE_CALLOC_PREFER_SPIRAM(1, payload_len);
    Icon* icons = NULL;
    size_t num_icons = 0;
    bcur_create_qr_icons(payload, payload_len, "test-type", qr_version, &icons, &num_icons);
    if (!icons || !num_icons) {
        FAIL();
    }
    for (size_t i = 0; i < num_icons; ++i) {
        JADE_ASSERT(icons[i].data);
        free(icons[i].data);
    }
    free(icons);
    free(payload);
    return true;
}

// NOTE: the bc-ur checks below are all pure algorithmic/software tests - they
// do not exercise any hardware.  They live here (rather than in the firmware
// 'debug_selfcheck()') because running them on the device significantly
// fragments the internal DRAM heap, and the firmware run adds nothing.
bool debug_selfcheck(jade_process_t* process)
{
    (void)process;

    // Test we can decode a sequence of qrcodes into a psbt and back
    if (!test_bcur_decode_encode()) {
        FAIL();
    }

    // Test various bc-ur bad inputs
    if (!test_bcur_decode_bad_cases()) {
        FAIL();
    }

    // Test we can render a small sequence of bcur qr-code icons in all supported qr versions
    if (!test_bcur_icons()) {
        FAIL();
    }

    // Test we can render a large sequence of bcur fragments (smallest supported qr version)
    if (!test_bcur_large_payload_many_icons()) {
        FAIL();
    }

    // Iterative check of bcur sizing macro
    if (!bcur_check_fragment_sizes()) {
        FAIL();
    }

    // PASS !
    return true;
}
