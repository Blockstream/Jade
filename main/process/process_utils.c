#ifndef AMALGAMATED_BUILD
#include "../descriptor.h"
#include "../identity.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../rsa.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "process_utils.h"

#include <sys/time.h>
#include <wally_address.h>
#include <wally_anti_exfil.h>
#include <wally_script.h>

#include "process_utils.h"

static const char KEY_TYPE_RSA[] = { 'R', 'S', 'A' };

bool jade_process_check_network(jade_process_t* process, CborValue* params, uint32_t* network_id)
{
    JADE_ASSERT(process);
    JADE_ASSERT(params);
    JADE_ASSERT(network_id);

    char network[MAX_NETWORK_NAME_LEN];
    size_t network_len;
    rpc_get_string("network", sizeof(network), params, network, &network_len);
    *network_id = network_from_name(network_len ? network : NULL);

    if (*network_id == WALLY_NETWORK_NONE) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid network from parameters", NULL);
        return false;
    }
    if (!keychain_is_network_id_consistent(*network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_NETWORK_MISMATCH, "Network type inconsistent with prior usage", NULL);
        return false;
    }
    return true;
}

// Sanity check extended-data payload fields
bool check_extended_data_fields(CborValue* params, const char* expected_origid, const char* expected_orig,
    const size_t expected_seqnum, const size_t expected_seqlen)
{
    JADE_ASSERT(params);
    JADE_ASSERT(expected_origid);
    JADE_ASSERT(expected_orig);

    const char* orig = NULL;
    size_t origlen = 0;
    rpc_get_string_ptr("orig", params, &orig, &origlen);

    char origid[MAXLEN_ID + 1];
    size_t origidlen = 0;
    rpc_get_string("origid", sizeof(origid), params, origid, &origidlen);

    const size_t len = strlen(expected_orig);
    if (origlen != len || strncmp(orig, expected_orig, len) || strcmp(origid, expected_origid)) {
        JADE_LOGE("Extended data origin fields mismatch");
        return false;
    }

    size_t nextseq = 0;
    size_t seqlen = 0;
    if (!rpc_get_sizet("seqlen", params, &seqlen) || seqlen != expected_seqlen
        || !rpc_get_sizet("seqnum", params, &nextseq) || nextseq != expected_seqnum) {
        JADE_LOGE("Extended data sequence fields mismatch");
        return false;
    }

    // Appears consistent and as expected
    return true;
}

// Extract 'epoch' field from message and use to set internal clock
int params_set_epoch_time(CborValue* params, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_INIT_OUT_PPTR(errmsg);

    uint64_t epoch = 0;
    if (!rpc_get_uint64_t("epoch", params, &epoch)) {
        *errmsg = "Failed to extract valid epoch value from parameters";
        return CBOR_RPC_BAD_PARAMETERS;
    }

    // Set the epoch time
    const struct timeval tv = { .tv_sec = epoch, .tv_usec = 0 };
    const int res = settimeofday(&tv, NULL);
    if (res) {
        JADE_LOGE("settimeofday() failed error: %d", res);
        *errmsg = "Failed to set time";
        return CBOR_RPC_INTERNAL_ERROR;
    }

    // Return no-error
    return 0;
}

// Identity, curve and index are always needed by the 'identity' functions.
bool params_identity_curve_index(CborValue* params, const char** identity, size_t* identity_len, const char** curve,
    size_t* curve_len, size_t* index, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_INIT_OUT_PPTR(identity);
    JADE_INIT_OUT_SIZE(identity_len);
    JADE_INIT_OUT_PPTR(curve);
    JADE_INIT_OUT_SIZE(curve_len);
    JADE_INIT_OUT_SIZE(index);
    JADE_INIT_OUT_PPTR(errmsg);

    rpc_get_string_ptr("identity", params, identity, identity_len);
    if (!*identity || *identity_len >= MAX_DISPLAY_MESSAGE_LEN
        || !is_identity_protocol_valid(*identity, *identity_len)) {
        *errmsg = "Failed to extract valid identity from parameters";
        return false;
    }

    rpc_get_string_ptr("curve", params, curve, curve_len);
    if (!*curve || !is_identity_curve_valid(*curve, *curve_len)) {
        *errmsg = "Failed to extract valid curve name from parameters";
        return false;
    }

    // index is optional
    if (rpc_has_field_data("index", params)) {
        if (!rpc_get_sizet("index", params, index)) {
            *errmsg = "Failed to extract valid index from parameters";
            return false;
        }
    }

    return true;
}

// Hash-prevouts and output index are needed to generate deterministic blinding factors.
bool params_hashprevouts_outputindex(CborValue* params, const uint8_t** hash_prevouts, size_t* hash_prevouts_len,
    size_t* output_index, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_INIT_OUT_PPTR(hash_prevouts);
    JADE_INIT_OUT_SIZE(hash_prevouts_len);
    JADE_INIT_OUT_SIZE(output_index);
    JADE_INIT_OUT_PPTR(errmsg);

    rpc_get_bytes_ptr("hash_prevouts", params, hash_prevouts, hash_prevouts_len);
    if (*hash_prevouts_len != SHA256_LEN) {
        *errmsg = "Failed to extract hash_prevouts from parameters";
        return false;
    }

    if (!rpc_get_sizet("output_index", params, output_index)) {
        *errmsg = "Failed to extract output index from parameters";
        return false;
    }

    return true;
}

// Read descriptor name and load the registration record.
bool params_load_descriptor(CborValue* params, char* descriptor_name, const size_t descriptor_name_len,
    descriptor_data_t* descriptor, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(descriptor_name);
    JADE_ASSERT(descriptor_name_len);
    JADE_ASSERT(descriptor);
    JADE_INIT_OUT_PPTR(errmsg);

    size_t written = 0;
    rpc_get_string("descriptor_name", descriptor_name_len, params, descriptor_name, &written);
    if (written == 0) {
        *errmsg = "Invalid descriptor name parameter";
        return false;
    }

    if (!descriptor_load_from_storage(descriptor_name, descriptor, errmsg)) {
        // 'errmsg' populated by above call
        return false;
    }

    return true;
}

// Read multisig name and load the registration record.
bool params_load_multisig(CborValue* params, char* multisig_name, const size_t multisig_name_len,
    multisig_data_t* multisig_data, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(multisig_name);
    JADE_ASSERT(multisig_name_len);
    JADE_ASSERT(multisig_data);
    JADE_INIT_OUT_PPTR(errmsg);

    size_t written = 0;
    rpc_get_string("multisig_name", multisig_name_len, params, multisig_name, &written);
    if (written == 0) {
        *errmsg = "Invalid multisig name parameter";
        return false;
    }

    // NOTE: can extend to pass signer_t structs here if we want full signer details
    if (!multisig_load_from_storage(multisig_name, multisig_data, NULL, 0, NULL, errmsg)) {
        // 'errmsg' populated by above call
        return false;
    }

    return true;
}

// Take a multisig record as above, then read out the signer path suffixes and derive the relevant pubkeys.
// Output any warning messages associated with the signer paths (eg. if they are non-standard, mismatch, etc)
// Required for generating multisig receive addresses and also change addresses (when auto-validating change).
bool params_multisig_pubkeys(const bool is_change, CborValue* params, multisig_data_t* multisig_data, uint8_t* pubkeys,
    const size_t pubkeys_len, size_t* pubkeys_written, char* warningmsg, size_t warningmsg_len, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(multisig_data);
    JADE_ASSERT(pubkeys);
    JADE_ASSERT(pubkeys_len == MAX_ALLOWED_SIGNERS * EC_PUBLIC_KEY_LEN);
    JADE_INIT_OUT_SIZE(pubkeys_written);
    JADE_ASSERT(warningmsg);
    JADE_ASSERT(warningmsg_len);
    JADE_INIT_OUT_PPTR(errmsg);

    // Validate paths
    CborValue all_signer_paths;
    bool all_paths_as_expected;
    bool final_elements_consistent;
    if (!rpc_get_array("paths", params, &all_signer_paths)
        || !multisig_validate_paths(is_change, &all_signer_paths, &all_paths_as_expected, &final_elements_consistent)) {
        *errmsg = "Failed to extract signer paths from parameters";
        return false;
    }

    // If paths are not as expected, see if we have a valid change/non-change path (when expecting the other)
    bool flipped_change_element = false;
    if (!all_paths_as_expected) {
        bool unused;
        multisig_validate_paths(!is_change, &all_signer_paths, &flipped_change_element, &unused);
    }

    // If paths not as expected show a warning message and ask the user to confirm
    if (!all_paths_as_expected || !final_elements_consistent) {
        const char* msg1 = "";
        if (!all_paths_as_expected) {
            if (flipped_change_element) {
                msg1 = is_change ? "\nExternal multisig path." : "\nMultisig change path.";
            } else {
                msg1 = "\nUnusual multisig path.";
            }
        }
        const char* msg2 = !final_elements_consistent ? "\nDiffering signer paths." : "";

        const char* heading = flipped_change_element && final_elements_consistent ? "Note" : "Warning";
        const int ret = snprintf(warningmsg, warningmsg_len, "%s:%s%s", heading, msg1, msg2);
        JADE_ASSERT(ret > 0 && ret < warningmsg_len);
    }

    if (!multisig_get_pubkeys(
            multisig_data->xpubs, multisig_data->num_xpubs, &all_signer_paths, pubkeys, pubkeys_len, pubkeys_written)
        || *pubkeys_written != multisig_data->num_xpubs * EC_PUBLIC_KEY_LEN) {
        *errmsg = "Unexpected number of signer paths or invalid path for multisig";
        return false;
    }

    return true;
}

// Get the relevant master blinding key (padded to 64-bytes for low-level calls).
// This may be the master key with a multisig registration (if indicated in the parameters).
// Otherwise, defaults to the master blinding key directly associated with this wallet/signer.
bool params_get_master_blindingkey(
    CborValue* params, uint8_t* master_blinding_key, const size_t master_blinding_key_len, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(master_blinding_key);
    JADE_ASSERT(master_blinding_key_len == HMAC_SHA512_LEN);
    JADE_INIT_OUT_PPTR(errmsg);

    // If no 'multisig_name' parameter, default to the signer's own master blinding key
    if (!rpc_has_field_data("multisig_name", params)) {
        memcpy(master_blinding_key, keychain_get()->master_unblinding_key, master_blinding_key_len);
        return true;
    }

    // If is multisig, extract master key from multisig record
    size_t written = 0;
    char multisig_name[MAX_MULTISIG_NAME_SIZE];
    rpc_get_string("multisig_name", sizeof(multisig_name), params, multisig_name, &written);
    if (written == 0) {
        *errmsg = "Invalid multisig name parameter";
        return false;
    }

    multisig_data_t multisig_data = { 0 };
    if (!multisig_load_from_storage(multisig_name, &multisig_data, NULL, 0, NULL, errmsg)) {
        // 'errmsg' populated by above call
        return false;
    }

    if (!multisig_get_master_blinding_key(&multisig_data, master_blinding_key, master_blinding_key_len, errmsg)) {
        // 'errmsg' populated by above call
        return false;
    }

    return true;
}

// Get the common parameters required when signing an tx input
bool params_tx_input_signing_data(const bool use_ae_signatures, CborValue* params, input_data_t* input_data,
    const uint8_t** ae_host_commitment, size_t* ae_host_commitment_len, const uint8_t** script, size_t* script_len,
    script_flavour_t* aggregate_script_flavour, const char** errmsg)
{
    // Ensure that input_data_t meets our expections
    JADE_STATIC_ASSERT(sizeof(((input_data_t*)0)->path) == MAX_PATH_LEN * sizeof(uint32_t));
    JADE_STATIC_ASSERT(sizeof(((input_data_t*)0)->id) == MAXLEN_ID + 1);
    JADE_ASSERT(params);
    JADE_ASSERT(input_data);
    JADE_INIT_OUT_PPTR(ae_host_commitment);
    JADE_INIT_OUT_SIZE(ae_host_commitment_len);
    JADE_INIT_OUT_PPTR(script);
    JADE_INIT_OUT_SIZE(script_len);
    JADE_ASSERT(aggregate_script_flavour);
    JADE_ASSERT(errmsg);

    bool is_witness;
    if (!rpc_get_boolean("is_witness", params, &is_witness)) {
        *errmsg = "Failed to extract is_witness from parameters";
        return false;
    }
    // Assume segwit v0 for witness inputs unless v1 is detected below
    input_data->sig_type = is_witness ? WALLY_SIGTYPE_SW_V0 : WALLY_SIGTYPE_PRE_SW;

    const size_t max_path_len = sizeof(input_data->path) / sizeof(input_data->path[0]);
    if (!rpc_get_bip32_path("path", params, input_data->path, max_path_len, &input_data->path_len)
        || input_data->path_len == 0) {
        *errmsg = "Failed to extract valid path from parameters";
        return false;
    }

    // Get any explicit sighash byte.
    // If one isn't given, we default it below according to the type
    // of the input prevout script before returning
    const bool have_sighash = rpc_has_field_data("sighash", params);
    if (have_sighash) {
        size_t sighash = 0;
        if (!rpc_get_sizet("sighash", params, &sighash) || sighash > UINT8_MAX) {
            *errmsg = "Failed to fetch valid sighash from parameters";
            return false;
        }
        input_data->sighash = (uint8_t)sighash;
    }

    if (use_ae_signatures) {
        // Using the anti-exfil signing flow.
        // Commitment data is optional on a per-input basis: If not provided
        // for a given input, a normal (non-AE) signature is generated.
        rpc_get_bytes_ptr("ae_host_commitment", params, ae_host_commitment, ae_host_commitment_len);
        if (*ae_host_commitment_len && *ae_host_commitment_len != WALLY_HOST_COMMITMENT_LEN) {
            *errmsg = "Failed to extract valid host commitment from parameters";
            return false;
        }
        // Record whether we should generate an AE signature for this input
        input_data->use_ae = *ae_host_commitment_len != 0;
    }

    // Get prevout script - required for signing inputs
    rpc_get_bytes_ptr("script", params, script, script_len);
    if (!*script || *script_len == 0) {
        *errmsg = "Failed to extract script from parameters";
        return false;
    }

    bool is_p2tr = false;
    const script_flavour_t script_flavour = get_script_flavour(*script, *script_len, &is_p2tr);
    if (is_p2tr) {
        if (input_data->use_ae) {
            // Taproot commitments must be empty, so that we can add anti-exfil
            // support later without backwards compatibility issues.
            *errmsg = "Invalid non-empty taproot host commitment";
            return false;
        }
        input_data->sig_type = WALLY_SIGTYPE_SW_V1;
    }
    // Track the types of the input prevout scripts
    update_aggregate_scripts_flavour(script_flavour, aggregate_script_flavour);

    if (!have_sighash) {
        // Default to SIGHASH_DEFAULT for taproot, or SIGHASH_ALL otherwise
        input_data->sighash = is_p2tr ? WALLY_SIGHASH_DEFAULT : WALLY_SIGHASH_ALL;
    }

    return true;
}

// Bip85 RSA key parameters (key size and index)
bool params_get_bip85_rsa_key(CborValue* params, size_t* key_bits, size_t* index, const char** errmsg)
{
    JADE_ASSERT(params);
    JADE_ASSERT(key_bits);
    JADE_ASSERT(index);
    JADE_INIT_OUT_PPTR(errmsg);

    // Only handle 'RSA' atm
    char key_type[8];
    size_t written = 0;
    rpc_get_string("key_type", sizeof(key_type), params, key_type, &written);
    if (written != sizeof(KEY_TYPE_RSA) || memcmp(key_type, KEY_TYPE_RSA, sizeof(KEY_TYPE_RSA))) {
        *errmsg = "Cannot extract valid key_type from parameters";
        return false;
    }

    // Get number of key_bits and final index
    if (!rpc_get_sizet("key_bits", params, key_bits) || *key_bits > MAX_RSA_GEN_KEY_LEN
        || !RSA_KEY_SIZE_VALID(*key_bits)) {
        *errmsg = "Failed to fetch valid key length from message";
        return false;
    }

    if (!rpc_get_sizet("index", params, index)) {
        *errmsg = "Failed to fetch valid index from message";
        return false;
    }

    return true;
}

// For now just return 'single-sig' or 'other'.
// In future may extend to include eg. 'green', 'other-multisig', etc.
script_flavour_t get_script_flavour(const uint8_t* script, const size_t script_len, bool* is_p2tr)
{
    size_t script_type;
    JADE_ASSERT(is_p2tr);
    *is_p2tr = false;
    JADE_WALLY_VERIFY(wally_scriptpubkey_get_type(script, script_len, &script_type));
    switch (script_type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
    case WALLY_SCRIPT_TYPE_P2WPKH:
        return SCRIPT_FLAVOUR_SINGLESIG;
    case WALLY_SCRIPT_TYPE_P2TR:
        *is_p2tr = true;
        return SCRIPT_FLAVOUR_SINGLESIG;
    case WALLY_SCRIPT_TYPE_MULTISIG:
        return SCRIPT_FLAVOUR_MULTISIG;
    default:
        // eg. ga-csv script
        return SCRIPT_FLAVOUR_OTHER;
    }
}

// Track the types of the input prevout scripts
void update_aggregate_scripts_flavour(
    const script_flavour_t new_script_flavour, script_flavour_t* aggregate_scripts_flavour)
{
    JADE_ASSERT(aggregate_scripts_flavour);
    if (*aggregate_scripts_flavour == SCRIPT_FLAVOUR_NONE) {
        // First script sets the 'aggregate_scripts_flavour'
        *aggregate_scripts_flavour = new_script_flavour;
    } else if (*aggregate_scripts_flavour != new_script_flavour) {
        // As soon as we see something differet, set to 'mixed'
        *aggregate_scripts_flavour = SCRIPT_FLAVOUR_MIXED;
    }
}

// eg:
// {
//   "http_request": {
//     //
//     "params": {
//       "urls": [],
//       "root_certificates": [`certificate`]'  ** optional
//       "method": "POST",                      ** optional
//       "accept": "json",                      ** optional
//       "data": `data`                         ** optional - can be text or binary
//     }
//     "on-reply": `on_reply`
//   }
void client_data_request_reply(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    JADE_ASSERT(container);

    const client_data_request_t* const request_data = (const client_data_request_t*)ctx;
    JADE_ASSERT(request_data->request_type);
    JADE_ASSERT(request_data->on_reply);
    // method, accept and certificate and data fields are optional, but some combinations may be nonsensical
    JADE_ASSERT(request_data->rawdata || !request_data->rawdata_len);

    const bool has_data_payload = request_data->strdata || (request_data->rawdata && request_data->rawdata_len);
    const bool nested_json = request_data->accept
        && (!strcmp(request_data->accept, "json") || !strcmp(request_data->accept, "application/json"));

    JADE_ASSERT(!nested_json || !request_data->rawdata_len);

    size_t num_params = 0;
    if (request_data->num_urls) {
        ++num_params;
    }
    if (request_data->method) {
        ++num_params;
    }
    if (request_data->accept) {
        ++num_params;
    }
    if (request_data->certificate) {
        ++num_params;
    }
    if (has_data_payload) {
        ++num_params;
    }

    CborEncoder root_map;
    CborError cberr = cbor_encoder_create_map(container, &root_map, 1);
    JADE_ASSERT(cberr == CborNoError);

    // Envelope data for client request
    cberr = cbor_encode_text_stringz(&root_map, request_data->request_type);
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder http_encoder;
    cberr = cbor_encoder_create_map(&root_map, &http_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encode_text_stringz(&http_encoder, "params");
    JADE_ASSERT(cberr == CborNoError);

    CborEncoder params_encoder;
    cberr = cbor_encoder_create_map(&http_encoder, &params_encoder, num_params);
    JADE_ASSERT(cberr == CborNoError);

    // The urls (http/tls/onion)
    if (request_data->num_urls) {
        add_string_array_to_map(&params_encoder, "urls", (const char**)request_data->urls, request_data->num_urls);
    }

    // Any additional root certificate that may be required
    if (request_data->certificate) {
        const char* root_certificates[] = { request_data->certificate };
        add_string_array_to_map(&params_encoder, "root_certificates", root_certificates, 1);
    }

    // The optional method (eg. GET/POST) and accept header (eg. json)
    if (request_data->method) {
        add_string_to_map(&params_encoder, "method", request_data->method);
    }
    if (request_data->accept) {
        add_string_to_map(&params_encoder, "accept", request_data->accept);
    }

    // Add payload data if passed
    if (has_data_payload) {
        if (request_data->rawdata_len) {
            // Binary blob
            add_bytes_to_map(&params_encoder, "data", request_data->rawdata, request_data->rawdata_len);
        } else if (!nested_json) {
            // Plain string
            add_string_to_map(&params_encoder, "data", request_data->strdata);
        } else {
            // Add additional layer of json
            cberr = cbor_encode_text_stringz(&params_encoder, "data");
            JADE_ASSERT(cberr == CborNoError);

            CborEncoder data_encoder;
            cberr = cbor_encoder_create_map(&params_encoder, &data_encoder, 1);
            JADE_ASSERT(cberr == CborNoError);

            // Payload data - one large opaque string
            // Test if character or binary string is based on length field
            add_string_to_map(&data_encoder, "data", request_data->strdata);

            cberr = cbor_encoder_close_container(&params_encoder, &data_encoder);
            JADE_ASSERT(cberr == CborNoError);
        }
    }

    cberr = cbor_encoder_close_container(&http_encoder, &params_encoder);
    JADE_ASSERT(cberr == CborNoError);

    // Add function to call with server's reply payload
    add_string_to_map(&http_encoder, "on-reply", request_data->on_reply);

    cberr = cbor_encoder_close_container(&root_map, &http_encoder);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encoder_close_container(container, &root_map);
    JADE_ASSERT(cberr == CborNoError);
}
#endif // AMALGAMATED_BUILD
