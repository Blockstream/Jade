#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "network.h"

#include <wally_address.h>
#include <wally_script.h>

#include <stdio.h>

static void base58_addr(uint8_t prefix, uint8_t* script, char** output)
{
    uint8_t decoded[21];
    decoded[0] = prefix;
    memcpy(decoded + 1, script, 20);
    JADE_WALLY_VERIFY(wally_base58_from_bytes(decoded, 21, BASE58_FLAG_CHECKSUM, output));
}

// Convert the passed btc script into an address
void script_to_address(const char* network, uint8_t* script, size_t script_len, char* output, size_t output_len)
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
void elements_script_to_address(const char* network, uint8_t* script, size_t script_len, const uint8_t* blinding_key,
    size_t blinding_key_len, char* output, size_t output_len)
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
