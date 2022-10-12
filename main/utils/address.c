#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "network.h"

#include <wally_address.h>
#include <wally_script.h>

#include <stdio.h>

static void base58_addr(const uint8_t prefix, const uint8_t* script, char** output)
{
    JADE_ASSERT(script);
    JADE_INIT_OUT_PPTR(output);

    uint8_t decoded[21];
    decoded[0] = prefix;
    memcpy(decoded + 1, script, 20);
    JADE_WALLY_VERIFY(wally_base58_from_bytes(decoded, 21, BASE58_FLAG_CHECKSUM, output));
}

static void render_op_return(const uint8_t* script, const size_t script_len, char* output, const size_t output_len)
{
    JADE_ASSERT(script);
    JADE_ASSERT(script_len > 0);
    JADE_ASSERT(script[0] == OP_RETURN);
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= 64); // sufficient to fit error 'too long' error message

    const char opdesc[] = "OP_RETURN: ";
    char* payload_hex = NULL;

    // Check data fits in output buffer, and verify push length matches data length
    if (script_len > 3 && script_len <= (output_len - sizeof(opdesc)) && script[1] == script_len - 2) {
        // Skip over the opcode and length, and hexlify the payload
        JADE_WALLY_VERIFY(wally_hex_from_bytes(script + 2, script_len - 2, &payload_hex));
        const int ret = snprintf(output, output_len, "%s%s", opdesc, payload_hex);
        JADE_ASSERT(ret > 0 && ret < output_len);
        free(payload_hex);
    } else {
        // Too long (or short!) or inconsistent to display - show length and error message
        const int ret = snprintf(output, output_len, "%s<script length: %u - cannot be displayed>", opdesc, script_len);
        JADE_ASSERT(ret > 0 && ret < output_len);
    }
}

// Convert the passed btc script into an address
void script_to_address(
    const char* network, const uint8_t* script, const size_t script_len, char* output, const size_t output_len)
{
    JADE_ASSERT(!isLiquidNetwork(network));

    int ret = 0;
    if (!script || !script_len) {
        ret = snprintf(output, output_len, "No Address");
        JADE_ASSERT(ret > 0 && ret < output_len);
        return;
    }

    size_t output_type;
    JADE_WALLY_VERIFY(wally_scriptpubkey_get_type(script, script_len, &output_type));

    char* tmp_str = NULL;
    uint8_t prefix = 0;
    const char* hrp = NULL;
    switch (output_type) {
    case WALLY_SCRIPT_TYPE_P2WPKH:
    case WALLY_SCRIPT_TYPE_P2WSH:
    case WALLY_SCRIPT_TYPE_P2TR:
        hrp = networkToBech32Hrp(network);
        JADE_ASSERT(hrp);
        JADE_WALLY_VERIFY(wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &tmp_str));
        break;

    case WALLY_SCRIPT_TYPE_P2PKH:
        prefix = networkToP2PKHPrefix(network);
        base58_addr(prefix, script + 3, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_P2SH:
        prefix = networkToP2SHPrefix(network);
        base58_addr(prefix, script + 2, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_OP_RETURN:
        render_op_return(script, script_len, output, output_len);
        break;

    default:
        ret = snprintf(output, output_len, "Unknown Address");
        JADE_ASSERT(ret > 0 && ret < output_len);
        break;
    }

    if (tmp_str) {
        ret = snprintf(output, output_len, "%s", tmp_str);
        JADE_ASSERT(ret > 0 && ret < output_len);
        JADE_WALLY_VERIFY(wally_free_string(tmp_str));
    }
}

// Convert the passed liquid script into an address (confidential if blindng key passed)
void elements_script_to_address(const char* network, const uint8_t* script, const size_t script_len,
    const uint8_t* blinding_key, const size_t blinding_key_len, char* output, const size_t output_len)
{
    JADE_ASSERT(isLiquidNetwork(network));

    int ret = 0;
    if (!script || !script_len) {
        ret = snprintf(output, output_len, "[FEE]");
        JADE_ASSERT(ret > 0 && ret < output_len);
        return;
    }

    size_t output_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    JADE_WALLY_VERIFY(wally_scriptpubkey_get_type(script, script_len, &output_type));

    char* tmp_str = NULL;
    uint8_t prefix = 0;
    const char* hrp = NULL;
    switch (output_type) {
    case WALLY_SCRIPT_TYPE_P2WPKH:
    case WALLY_SCRIPT_TYPE_P2WSH:
    case WALLY_SCRIPT_TYPE_P2TR:
        hrp = networkToBech32Hrp(network);
        JADE_ASSERT(hrp);
        JADE_WALLY_VERIFY(wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &tmp_str));
        break;

    case WALLY_SCRIPT_TYPE_P2PKH:
        prefix = networkToP2PKHPrefix(network);
        base58_addr(prefix, script + 3, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_P2SH:
        prefix = networkToP2SHPrefix(network);
        base58_addr(prefix, script + 2, &tmp_str);
        break;

    case WALLY_SCRIPT_TYPE_OP_RETURN:
        render_op_return(script, script_len, output, output_len);
        break;

    default:
        // add a "[C]" prefix to show that the address is confidential
        ret = snprintf(output, output_len, "%sUnknown Address", blinding_key ? "[C] " : "");
        JADE_ASSERT(ret > 0 && ret < output_len);
        break;
    }

    if (blinding_key) {
        char* conf_tmp_str = NULL;
        const char* hrpConfidential = NULL;

        switch (output_type) {
        case WALLY_SCRIPT_TYPE_P2WPKH:
        case WALLY_SCRIPT_TYPE_P2WSH:
            hrpConfidential = networkToBlech32Hrp(network);
            JADE_ASSERT(hrpConfidential);
            wally_confidential_addr_from_addr_segwit(
                tmp_str, hrp, hrpConfidential, blinding_key, blinding_key_len, &conf_tmp_str);
            break;

        case WALLY_SCRIPT_TYPE_P2PKH:
        case WALLY_SCRIPT_TYPE_P2SH:
            prefix = networkToCAPrefix(network);
            wally_confidential_addr_from_addr(tmp_str, prefix, blinding_key, blinding_key_len, &conf_tmp_str);
            break;
        }

        // swap the ptr
        if (conf_tmp_str) {
            JADE_WALLY_VERIFY(wally_free_string(tmp_str));
            tmp_str = conf_tmp_str;
        }
    }

    if (tmp_str) {
        ret = snprintf(output, output_len, "%s", tmp_str);
        JADE_ASSERT(ret > 0 && ret < output_len);
        JADE_WALLY_VERIFY(wally_free_string(tmp_str));
    }
}
