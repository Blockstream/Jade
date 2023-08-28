#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/event.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../utils/util.h"
#include "../wallet.h"

#include "process_utils.h"

#include <ctype.h>
#include <sodium/utils.h>

// Multisig registration file, field names
static const char MSIG_FILE_NAME[] = "Name";
static const char MSIG_FILE_FORMAT[] = "Format";
static const char MSIG_FILE_SORTED[] = "Sorted";
static const char MSIG_FILE_POLICY[] = "Policy";
static const char MSIG_FILE_DERIVATION[] = "Derivation";

bool show_multisig_activity(const char* multisig_name, bool is_sorted, size_t threshold, size_t num_signers,
    const signer_t* signer_details, const size_t num_signer_details, const char* master_blinding_key_hex,
    const uint8_t* wallet_fingerprint, size_t wallet_fingerprint_len, bool initial_confirmation, bool overwriting,
    bool is_valid);

// Function to validate multsig parameters and persist the record
static int register_multisig(const char* multisig_name, const char* network, const script_variant_t script_variant,
    const bool sorted, const size_t threshold, const signer_t* signers, const size_t num_signers,
    const uint8_t* master_blinding_key, const size_t master_blinding_key_len, const char** errmsg)
{
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(isValidNetwork(network));
    JADE_ASSERT(is_multisig(script_variant));
    JADE_ASSERT(threshold);
    JADE_ASSERT(signers);
    JADE_ASSERT(num_signers);
    JADE_INIT_OUT_PPTR(errmsg);

    if (!storage_key_name_valid(multisig_name)) {
        *errmsg = "Invalid multisig name";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    if (num_signers > MAX_MULTISIG_SIGNERS) {
        *errmsg = "Failed to extract co-signers";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    if (threshold > num_signers) {
        *errmsg = "Invalid multisig threshold";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Validate signers
    size_t total_num_path_elements = 0;
    uint8_t wallet_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(wallet_fingerprint, sizeof(wallet_fingerprint));
    if (!multisig_validate_signers(
            signers, num_signers, wallet_fingerprint, sizeof(wallet_fingerprint), &total_num_path_elements)) {
        *errmsg = "Failed to validate co-signers";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    int retval = 0;
    const size_t registration_len = MULTISIG_BYTES_LEN(master_blinding_key_len, num_signers, total_num_path_elements);
    uint8_t* const registration = JADE_MALLOC(registration_len);
    if (!multisig_data_to_bytes(script_variant, sorted, threshold, master_blinding_key, master_blinding_key_len,
            signers, num_signers, total_num_path_elements, registration, registration_len)) {
        *errmsg = "Failed to serialise multisig";
        retval = CBOR_RPC_INTERNAL_ERROR;
        goto cleanup;
    }

    // See if a record for this name exists already
    const bool overwriting = storage_multisig_name_exists(multisig_name);

    // If so, see if it is identical to the record we are trying to persist
    // - if so, just return true immediately.
    if (overwriting) {
        size_t written = 0;
        uint8_t* const existing = JADE_MALLOC(registration_len);
        if (storage_get_multisig_registration(multisig_name, existing, sizeof(existing), &written)
            && written == registration_len && !sodium_memcmp(existing, registration, registration_len)) {
            JADE_LOGI("Multisig %s: identical registration exists, returning immediately", multisig_name);
            free(existing);
            goto cleanup;
        }
        free(existing);
    } else {
        // Not overwriting an existing record - check storage slot available
        if (storage_get_multisig_registration_count() >= MAX_MULTISIG_REGISTRATIONS) {
            *errmsg = "Already have maximum number of multisig wallets";
            retval = CBOR_RPC_BAD_PARAMETERS;
            goto cleanup;
        }
    }

    // Check to see whether user accepted or declined
    char* master_blinding_key_hex = NULL;
    if (master_blinding_key_len) {
        JADE_WALLY_VERIFY(wally_hex_from_bytes(master_blinding_key, master_blinding_key_len, &master_blinding_key_hex));
    }
    // Check to see whether user accepted or declined
    const bool is_valid = true;
    const bool initial_confirmation = true;
    const bool confirmed = show_multisig_activity(multisig_name, sorted, threshold, num_signers, signers, num_signers,
        master_blinding_key_hex, wallet_fingerprint, sizeof(wallet_fingerprint), initial_confirmation, overwriting,
        is_valid);
    if (master_blinding_key_hex) {
        JADE_WALLY_VERIFY(wally_free_string(master_blinding_key_hex));
    }

    if (!confirmed) {
        JADE_LOGW("User declined to register multisig");
        *errmsg = "User declined to register multisig";
        retval = CBOR_RPC_USER_CANCELLED;
        goto cleanup;
    }

    JADE_LOGD("User accepted multisig");

    // Persist multisig registration in nvs
    if (!storage_set_multisig_registration(multisig_name, registration, registration_len)) {
        *errmsg = "Failed to persist multisig data";
        await_error_activity("Error saving multisig");
        retval = CBOR_RPC_INTERNAL_ERROR;
        goto cleanup;
    }

cleanup:
    free(registration);
    return retval;
}

// Helper to get next line from a file/string
// State kept externally in ptr/eol so should repeatedly pass in same parameters
// which are updated to indicate new/next line limits.
static bool get_next_line(const char** ptr, const char** eol, const char* const eof)
{
    JADE_ASSERT(ptr);
    JADE_ASSERT(*ptr);
    JADE_ASSERT(eol);
    JADE_ASSERT(eof);

    while (true) {
        if (*eol) {
            if (*eol >= eof) {
                // Exhausted file
                JADE_LOGD("Exhausted file");
                return false;
            }
            *ptr = *eol + 1;
        }

        // Find line end
        *eol = memchr(*ptr, '\n', eof - *ptr);
        if (!*eol) {
            *eol = eof;
        }
        JADE_ASSERT(*eol <= eof);

        // Skip if line empty or a comment
        if (*ptr >= *eol || **ptr == '#') {
            continue;
        }

        JADE_ASSERT(*ptr < *eol);
        JADE_ASSERT(*ptr < eof);
        return true;
    }
}

// Helper to split 'name: value' line from multisig registration file.
// ptr and eol are line limits as above.  name_end indicates the end of the 'name' part.
// The value part is copied into the passed output buffer.
static bool split_line(
    const char* ptr, const char* eol, size_t* name_len, char* output, const size_t output_len, size_t* written)
{
    JADE_ASSERT(ptr);
    JADE_ASSERT(eol);
    JADE_INIT_OUT_SIZE(name_len);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len);
    JADE_INIT_OUT_SIZE(written);

    JADE_ASSERT(ptr < eol);

    // Split into name/value
    const char* p = memchr(ptr, ':', eol - ptr);
    if (!p || p <= ptr) {
        JADE_LOGW("Mising delimiter in multisig file line: %.*s", eol - ptr, ptr);
        return false;
    }
    *name_len = p - ptr;

    // Skip delimiter and any white space
    while (p < eol && isspace((unsigned char)*++p)) {
        // Skip
    }

    // Fail if value too long
    *written = eol - p;
    if (!*written || *written >= output_len) {
        JADE_LOGW("Item value missing or too long in multisig file line: %.*s", eol - ptr, ptr);
        return false;
    }

    // Copy and nul-terminate value string
    memcpy(output, p, *written);
    output[*written] = '\0';
    return true;
}

// Flags to cache which records we have seen
#define FIELD_NAME 0x1
#define FIELD_POLICY 0x2
#define FIELD_FORMAT 0x4
#define FIELD_SORTED 0x8
#define FIELD_DERIVATION 0x10

// Match the current line to a specific trial field, passed as a char[]
#define IS_FIELD(field) (name_len == sizeof(field) - 1 && !strncasecmp(field, read_ptr, name_len))

// Function to read a multisig file, and if possible register the multisig
int register_multisig_file(const char* multisig_file, const size_t multisig_file_len, const char** errmsg)
{
    JADE_ASSERT(multisig_file);
    JADE_ASSERT(multisig_file_len);
    JADE_INIT_OUT_PPTR(errmsg);

    // Work out network and appropriate xpub version bytes
    const char* network = NULL;
    uint8_t xpub_version[4];
    if (keychain_get_network_type_restriction() == NETWORK_TYPE_TEST) {
        network = TAG_TESTNET;
        uint32_to_be(BIP32_VER_TEST_PUBLIC, xpub_version);
    } else {
        network = TAG_MAINNET;
        uint32_to_be(BIP32_VER_MAIN_PUBLIC, xpub_version);
    }

    // The values we need to populate
    char multisig_name[MAX_MULTISIG_NAME_SIZE];
    bool name_truncated = false;
    script_variant_t script_variant = GREEN; // invalid for this case
    size_t threshold = 0;
    size_t nsigners = 0; // total number of signers
    size_t isigner = 0; // signers so far populated
    signer_t* signers = NULL;

    // Optional 'sorted multi' field
    bool sorted = true; // for historical reasons defaults to 'true'

    // Not supported by the file format ?
    const uint8_t* blinding_key = NULL;
    const size_t blinding_key_len = 0;

    // Current signer's derivation path
    // (Can be global, or set per signer)
    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;

    // Keep track of which fields we've read thus far
    uint8_t fields_read = 0;
    int retval = CBOR_RPC_BAD_PARAMETERS;

    // These hold the state of the file/string reader and are updated by the loop
    const char* read_ptr = multisig_file;
    const char* eol = NULL;
    const char* const eof = multisig_file + multisig_file_len;

    while (get_next_line(&read_ptr, &eol, eof)) {
        JADE_LOGI("Processing line: %.*s", eol - read_ptr, read_ptr);

        size_t name_len = 0;
        size_t value_len = 0;
        char value[128]; // should be sufficent for all valid values - eg. xpub
        if (!split_line(read_ptr, eol, &name_len, value, sizeof(value), &value_len) || !value_len) {
            JADE_LOGE("Failed to process multisig file line: %.*s", eol - read_ptr, read_ptr);
            *errmsg = "Invalid multisig file";
            goto cleanup;
        }
        const char* const value_end = value + value_len;
        JADE_ASSERT(*value_end == '\0');

        // Handle lines
        if (IS_FIELD(MSIG_FILE_NAME)) {
            if (fields_read & FIELD_NAME) {
                JADE_LOGE("Repeated multisig name");
                *errmsg = "Invalid multisig file";
                goto cleanup;
            }
            // Multisig name - check length
            strncpy(multisig_name, value, sizeof(multisig_name));
            if (value_len >= MAX_MULTISIG_NAME_SIZE) {
                multisig_name[sizeof(multisig_name) - 1] = '\0';
                name_truncated = true;
                JADE_LOGW("Multisig name too long - truncating: '%s' to '%s'", value, multisig_name);
            }
            // Attempt to sanitize name string
            for (char* pch = multisig_name; *pch; ++pch) {
                JADE_ASSERT(pch < multisig_name + sizeof(multisig_name));
                // Change spaces to underscores
                if (isspace((unsigned char)*pch)) {
                    *pch = '_';
                }
            }
            if (!storage_key_name_valid(multisig_name)) {
                JADE_LOGE("Invalid multisig name: %s", multisig_name);
                *errmsg = "Invalid multisig name";
                goto cleanup;
            }
            fields_read |= FIELD_NAME;
        } else if (IS_FIELD(MSIG_FILE_POLICY)) {
            if (fields_read & FIELD_POLICY) {
                JADE_LOGE("Repeated multisig policy");
                *errmsg = "Invalid multisig file";
                goto cleanup;
            }

            // "N of M"
            char* space1 = memchr(value, ' ', value_len);
            char* space2 = space1 ? memchr(space1 + 1, ' ', value_end - (space1 + 1)) : NULL;
            if (!space1 || !space2 || space1 > value_end || space2 > value_end) {
                JADE_LOGE("Invalid multisig policy: %s", value);
                *errmsg = "Invalid multisig policy";
                goto cleanup;
            }

            // Overwrite the spaces with '\0's to split into 3 strings - N, 'of', M
            *space1 = '\0';
            *space2 = '\0';

            // Read numeric values
            char* end1 = NULL;
            threshold = strtoul(value, &end1, 10);
            char* end2 = NULL;
            nsigners = strtoul(space2 + 1, &end2, 10);
            if (!threshold || !nsigners || threshold > nsigners || nsigners > MAX_MULTISIG_SIGNERS || end1 != space1
                || end2 != value_end || strcasecmp(space1 + 1, "of")) {
                JADE_LOGE("Invalid multisig policy %s %s %s", value, space1, space2);
                *errmsg = "Invalid multisig policy";
                goto cleanup;
            }

            // Allocate the signers block for that many signers
            JADE_ASSERT(!signers);
            signers = JADE_CALLOC(nsigners, sizeof(signer_t));
            fields_read |= FIELD_POLICY;
        } else if (IS_FIELD(MSIG_FILE_FORMAT)) {
            if (fields_read & FIELD_FORMAT) {
                JADE_LOGE("Repeated multisig format");
                *errmsg = "Invalid multisig file";
                goto cleanup;
            }

            // Script type
            if (!strcasecmp(value, "P2WSH")) {
                script_variant = MULTI_P2WSH;
            } else if (!strcasecmp(value, "P2WSH-P2SH") || !strcasecmp(value, "P2SH-P2WSH")) {
                script_variant = MULTI_P2WSH_P2SH;
            } else if (!strcasecmp(value, "P2SH")) {
                script_variant = MULTI_P2SH;
            } else {
                JADE_LOGE("Invalid multisig format: %s", value);
                *errmsg = "Invalid multisig format";
                goto cleanup;
            }
            fields_read |= FIELD_FORMAT;
        } else if (IS_FIELD(MSIG_FILE_SORTED)) {
            if (fields_read & FIELD_SORTED) {
                JADE_LOGE("Repeated sorted flag");
                *errmsg = "Invalid multisig file";
                goto cleanup;
            }

            // Sorted-multi?
            if (!strcasecmp(value, "TRUE")) {
                sorted = true;
            } else if (!strcasecmp(value, "FALSE")) {
                sorted = false;
            } else {
                JADE_LOGE("Invalid sorted flag: %s", value);
                *errmsg = "Invalid sorted flag";
                goto cleanup;
            }
            fields_read |= FIELD_SORTED;
        } else if (IS_FIELD(MSIG_FILE_DERIVATION)) {
            // "m/a/b/c/d" - accepts m/ or M/ as master, and h, H or ' as hardened indicators
            // NOTE: allowed to see derivation element multiple times (eg once per signer)
            if (!wallet_bip32_path_from_str(value, value_end - value, path, sizeof(path) / sizeof(path[0]), &path_len)
                || !path_len) {
                JADE_LOGE("Invalid derivation path: %s", value);
                *errmsg = "Invalid derivation path";
                goto cleanup;
            }
            fields_read |= FIELD_DERIVATION;
        } else if (name_len == BIP32_KEY_FINGERPRINT_LEN * 2) {
            // Assume <fingerprint>: <xpub>
            // Must have all other mandatory fields before we get to signers
            // (NOTE: for historical reasons 'sorted' field is optional)
            if ((fields_read & ~FIELD_SORTED) != (FIELD_NAME | FIELD_POLICY | FIELD_FORMAT | FIELD_DERIVATION)) {
                JADE_LOGE("Insufficient information read from multisig file when signers reached: %u", fields_read);
                *errmsg = "Insufficient information records";
                goto cleanup;
            }
            if (isigner >= nsigners || !nsigners) {
                JADE_LOGE("Unexpected number of signers for %u-of-%u policy", threshold, nsigners);
                *errmsg = "Invalid number of signers";
                goto cleanup;
            }
            JADE_ASSERT(signers);

            // Fingerprint
            size_t written = 0;
            if (wally_hex_n_to_bytes(
                    read_ptr, name_len, signers[isigner].fingerprint, sizeof(signers[isigner].fingerprint), &written)
                    != WALLY_OK
                || written != BIP32_KEY_FINGERPRINT_LEN) {
                JADE_LOGE("Error in fingerprint hex: %.*s", name_len, read_ptr);
                *errmsg = "Invalid signer fingerprint";
                goto cleanup;
            }

            // Derivation
            const size_t path_len_bytes = path_len * sizeof(uint32_t);
            if (!path_len || path_len_bytes > sizeof(signers[isigner].derivation)) {
                JADE_LOGE("Unexpected derivation path size: %u", path_len);
                *errmsg = "Derivation path too long";
                goto cleanup;
            }
            memcpy(signers[isigner].derivation, path, path_len_bytes);
            signers[isigner].derivation_len = path_len;
            signers[isigner].path_len = 0; // unused

            // Xpub
            uint8_t serialised[BIP32_SERIALIZED_LEN + BASE58_CHECKSUM_LEN];
            if (value_len < sizeof(xpub_version) || value_len >= sizeof(signers[isigner].xpub)
                || wally_base58_to_bytes(value, BASE58_FLAG_CHECKSUM, serialised, sizeof(serialised), &written)
                    != WALLY_OK
                || written != BIP32_SERIALIZED_LEN) {
                JADE_LOGE("Invalid xpub: %s", value);
                *errmsg = "Invalid signer xpub";
                goto cleanup;
            }

            // Wally only supports xpub and tpub prefixes, so force these prefix bytes
            // if the file xpub has some other prefix - eg. Ypub or Zpub etc.
            if (!memcmp(serialised, &xpub_version, sizeof(xpub_version))) {
                // Version bytes as expected
                strcpy(signers[isigner].xpub, value);
                signers[isigner].xpub_len = value_len;
            } else {
                JADE_LOGI("Overwriting xpub version bytes");

                char* xpub = NULL;
                memcpy(serialised, xpub_version, sizeof(xpub_version));
                if (wally_base58_from_bytes(serialised, written, BASE58_FLAG_CHECKSUM, &xpub) != WALLY_OK || !xpub) {
                    JADE_LOGE("Problem overwriting xpub version: %s", value);
                    *errmsg = "Invalid signer xpub";
                    goto cleanup;
                }
                JADE_LOGI("new xpub: %s", xpub);

                const size_t new_len = strlen(xpub);
                JADE_ASSERT(new_len < sizeof(signers[isigner].xpub));
                strcpy(signers[isigner].xpub, xpub);
                signers[isigner].xpub_len = new_len;
                JADE_WALLY_VERIFY(wally_free_string(xpub));
            }

            // Done - this signer complete
            ++isigner;
        } else {
            JADE_LOGE("Unexpected line in multisig file: %.*s", eol - read_ptr, read_ptr);
            *errmsg = "Invalid multisig file";
            goto cleanup;
        }
    };
    JADE_LOGD("Processing multisig file complete: %u", fields_read);

    // File exhausted - did we read all required data (Note: 'sorted' is optional)
    if ((fields_read & ~FIELD_SORTED) != (FIELD_NAME | FIELD_POLICY | FIELD_FORMAT | FIELD_DERIVATION)) {
        JADE_LOGE("Insufficient information read from multisig file: %u", fields_read);
        *errmsg = "Insufficient information records";
        goto cleanup;
    }
    if (isigner != nsigners || !nsigners) {
        JADE_LOGE("Unexpected number of signers for %u-of-%u policy", threshold, nsigners);
        *errmsg = "Invalid number of signers";
        goto cleanup;
    }

    // If 'name' was truncated, ask user to confirm
    if (name_truncated) {
        JADE_ASSERT(strlen(multisig_name) == sizeof(multisig_name) - 1);
        if (!await_yesno_activity("Confirm Multisig",
                "  Multisig record name\n  too long! Truncate to\n       15 characters?", false, NULL)) {
            JADE_LOGW("User declined truncating multisig record name to: %s", multisig_name);
            *errmsg = "Invalid multisig name";
            goto cleanup;
        }
    }

    // Try to register multisig!
    retval = register_multisig(multisig_name, network, script_variant, sorted, threshold, signers, nsigners,
        blinding_key, blinding_key_len, errmsg);
    if (retval) {
        JADE_LOGE("Failed to register multisig record: %s", *errmsg);
        goto cleanup;
    }

cleanup:
    free(signers);
    return retval;
}

// Helper to collect signers' details from input cbor message
static void get_signers_allocate(const char* field, const CborValue* value, signer_t** data, size_t* written)
{
    JADE_ASSERT(field);
    JADE_ASSERT(value);
    JADE_INIT_OUT_PPTR(data);
    JADE_INIT_OUT_SIZE(written);

    CborValue result;
    if (!rpc_get_array(field, value, &result)) {
        return;
    }

    size_t num_array_items = 0;
    CborError cberr = cbor_value_get_array_length(&result, &num_array_items);
    if (cberr != CborNoError || !num_array_items) {
        return;
    }

    CborValue arrayItem;
    cberr = cbor_value_enter_container(&result, &arrayItem);
    if (cberr != CborNoError || !cbor_value_is_valid(&arrayItem)) {
        return;
    }

    signer_t* const signers = JADE_CALLOC(num_array_items, sizeof(signer_t));

    for (size_t i = 0; i < num_array_items; ++i) {
        JADE_ASSERT(!cbor_value_at_end(&arrayItem));
        signer_t* const signer = signers + i;

        if (!cbor_value_is_map(&arrayItem)) {
            free(signers);
            return;
        }

        size_t num_map_items = 0;
        if (cbor_value_get_map_length(&arrayItem, &num_map_items) == CborNoError && num_map_items == 0) {
            CborError err = cbor_value_advance(&arrayItem);
            JADE_ASSERT(err == CborNoError);
            continue;
        }

        if (!rpc_get_n_bytes("fingerprint", &arrayItem, sizeof(signer->fingerprint), signer->fingerprint)) {
            free(signers);
            return;
        }

        if (!rpc_get_bip32_path("derivation", &arrayItem, signer->derivation, MAX_PATH_LEN, &signer->derivation_len)) {
            free(signers);
            return;
        }

        rpc_get_string("xpub", sizeof(signer->xpub), &arrayItem, signer->xpub, &signer->xpub_len);
        if (!signer->xpub_len || signer->xpub_len >= sizeof(signer->xpub)) {
            free(signers);
            return;
        }

        if (!rpc_get_bip32_path("path", &arrayItem, signer->path, MAX_PATH_LEN, &signer->path_len)) {
            free(signers);
            return;
        }

        CborError err = cbor_value_advance(&arrayItem);
        JADE_ASSERT(err == CborNoError);
    }

    cberr = cbor_value_leave_container(&result, &arrayItem);
    if (cberr != CborNoError) {
        free(signers);
        return;
    }

    *written = num_array_items;
    *data = signers;
}

void register_multisig_process(void* process_ptr)
{
    JADE_LOGI("Starting: %lu", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    char network[MAX_NETWORK_NAME_LEN];
    char multisig_name[MAX_MULTISIG_NAME_SIZE];
    char variant[MAX_VARIANT_LEN];
    const char* errmsg = NULL;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_multisig");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    // We accept a multisig file, as produced by several wallet apps
    if (rpc_has_field_data("multisig_file", &params)) {
        const char* multisig_file = NULL;
        size_t multisig_file_len = 0;
        rpc_get_string_ptr("multisig_file", &params, &multisig_file, &multisig_file_len);
        if (!multisig_file || !multisig_file_len) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid multisig file data", NULL);
            goto cleanup;
        }

        const int errcode = register_multisig_file(multisig_file, multisig_file_len, &errmsg);
        if (errcode) {
            jade_process_reject_message(process, errcode, errmsg, NULL);
            goto cleanup;
        }

        // Ok, all verified and persisted
        jade_process_reply_to_message_ok(process);
        JADE_LOGI("Success");
        return;
    }

    // Otherwise expect our original message fields

    // Check network is valid and consistent with prior usage
    size_t written = 0;
    rpc_get_string("network", sizeof(network), &params, network, &written);
    CHECK_NETWORK_CONSISTENT(process, network, written);

    // Get name of multisig wallet
    written = 0;
    rpc_get_string("multisig_name", sizeof(multisig_name), &params, multisig_name, &written);
    if (written == 0 || !storage_key_name_valid(multisig_name)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Missing or invalid multisig name parameter", NULL);
        goto cleanup;
    }

    CborValue descriptor;
    if (!rpc_get_map("descriptor", &params, &descriptor)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Cannot extract multisig descriptor data", NULL);
        goto cleanup;
    }

    // Handle script variants.
    written = 0;
    script_variant_t script_variant;
    rpc_get_string("variant", sizeof(variant), &descriptor, variant, &written);
    if (!get_script_variant(variant, written, &script_variant) || !is_multisig(script_variant)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid script variant parameter", NULL);
        goto cleanup;
    }

    // Handle sorted-multisig - defaults to false if not passed
    bool sorted = false;
    if (rpc_has_field_data("sorted", &descriptor)) {
        if (!rpc_get_boolean("sorted", &descriptor, &sorted)) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid sorted flag value", NULL);
            goto cleanup;
        }
    }

    // Liquid master blinding key for this multisig wallet
    const uint8_t* master_blinding_key = NULL;
    size_t master_blinding_key_len = 0;
    if (rpc_has_field_data("master_blinding_key", &descriptor)) {
        rpc_get_bytes_ptr("master_blinding_key", &descriptor, &master_blinding_key, &master_blinding_key_len);
        if (!master_blinding_key || master_blinding_key_len != MULTISIG_MASTER_BLINDING_KEY_SIZE) {
            jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid blinding key value", NULL);
            goto cleanup;
        }
    }

    // Threshold
    written = 0;
    rpc_get_sizet("threshold", &descriptor, &written);
    if (written == 0 || written > MAX_MULTISIG_SIGNERS) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid multisig threshold value", NULL);
        goto cleanup;
    }
    const uint8_t threshold = (uint8_t)written;

    // Co-Signers
    signer_t* signers = NULL;
    size_t num_signers = 0;
    get_signers_allocate("signers", &descriptor, &signers, &num_signers);
    if (num_signers == 0) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid co-signers from parameters", NULL);
        goto cleanup;
    }
    jade_process_free_on_exit(process, signers);

    const int errcode = register_multisig(multisig_name, network, script_variant, sorted, threshold, signers,
        num_signers, master_blinding_key, master_blinding_key_len, &errmsg);
    if (errcode) {
        jade_process_reject_message(process, errcode, errmsg, NULL);
        goto cleanup;
    }

    // Ok, all verified and persisted
    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    return;
}
