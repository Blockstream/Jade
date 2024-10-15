#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_bip85.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include "utils/shake256.h"
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

static void print_help(void)
{
    printf("Usage: ./bip85_rsa_key_gen --mnemonic <mnemonic> [--passphrase <passphrase>] --xpriv <xpriv> --index "
           "<index> --key_bits <bits>\n");
}

static void print_rsa_key(uint32_t bits_size, uint8_t* entropy, size_t entropy_size)
{
    assert(bits_size);
    assert(entropy);
    assert(entropy_size == 64);

    mbedtls_rsa_context ctx = {};
    mbedtls_rsa_init(&ctx);

    struct shake256_ctx sctx = {};
    shake256_init(&sctx, entropy, entropy_size);
    mbedtls_rsa_gen_key(&ctx, shake256_mbedtls_rnd_cb, &sctx, bits_size, 65537);

    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    const size_t output_buf_size = 6000;
    unsigned char* output_buf = malloc(output_buf_size);
    assert(output_buf);

    if (mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        printf("Failed to setup PK context\n");
        assert(0);
    }

    if (mbedtls_rsa_copy(mbedtls_pk_rsa(pk_ctx), &ctx) != 0) {
        printf("Failed to copy RSA context\n");
        assert(0);
    }

    if (mbedtls_pk_write_key_pem(&pk_ctx, output_buf, output_buf_size) != 0) {
        printf("Failed to write private key to PEM\n");
        assert(0);
    }

    printf("RSA Private Key in PEM format:\n%s\n", output_buf);

    unsigned char private_key_hash[SHA256_LEN];
    char* private_key_hash_hex = NULL;
    int wallyres = wally_sha256(output_buf, strlen((char*)output_buf), private_key_hash, SHA256_LEN);
    assert(wallyres == WALLY_OK);
    wallyres = wally_hex_from_bytes(private_key_hash, SHA256_LEN, &private_key_hash_hex);
    assert(wallyres == WALLY_OK);
    printf("SHA256 hash of Private Key PEM (hex): %s\n", private_key_hash_hex);

    if (mbedtls_pk_write_pubkey_pem(&pk_ctx, output_buf, output_buf_size) != 0) {
        printf("Failed to write public key to PEM\n");
        assert(0);
    }

    printf("RSA Public Key in PEM format:\n%s\n", output_buf);

    unsigned char public_key_hash[SHA256_LEN];
    char* public_key_hash_hex = NULL;
    wallyres = wally_sha256(output_buf, strlen((char*)output_buf), public_key_hash, SHA256_LEN);
    assert(wallyres == WALLY_OK);
    wallyres = wally_hex_from_bytes(public_key_hash, SHA256_LEN, &public_key_hash_hex);
    assert(wallyres == WALLY_OK);
    printf("SHA256 hash of Public Key PEM (hex): %s\n", public_key_hash_hex);

    wally_free_string(private_key_hash_hex);
    wally_free_string(public_key_hash_hex);
    free(output_buf);
    mbedtls_pk_free(&pk_ctx);
    mbedtls_rsa_free(&ctx);
}

int main(int argc, char* argv[])
{
    char* mnemonic = NULL;
    char* xpriv = NULL;
    char* passphrase = "";
    int index = -1;
    int key_bits = -1;
    int mnemonic_set = 0;
    int xpriv_set = 0;
    int index_set = 0;
    int key_bits_set = 0;
    int passphrase_set = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mnemonic") == 0) {
            if (i + 1 < argc) {
                mnemonic = argv[++i];
                mnemonic_set = 1;
            }
        } else if (strcmp(argv[i], "--xpriv") == 0) {
            if (i + 1 < argc) {
                xpriv = argv[++i];
                xpriv_set = 1;
            }
        } else if (strcmp(argv[i], "--index") == 0) {
            if (i + 1 < argc) {
                index = atoi(argv[++i]);
                if (index >= 0)
                    index_set = 1;
            }
        } else if (strcmp(argv[i], "--key_bits") == 0) {
            if (i + 1 < argc) {
                key_bits = atoi(argv[++i]);
                if (key_bits > 0)
                    key_bits_set = 1;
            }
        } else if (strcmp(argv[i], "--passphrase") == 0) {
            if (i + 1 < argc) {
                passphrase = argv[++i];
                passphrase_set = 1;
            }
        }
    }

    if ((mnemonic_set && xpriv_set) || (!mnemonic_set && !xpriv_set) || !index_set || !key_bits_set) {
        printf("Error: Invalid parameters. --mnemonic and --xpriv are mutually exclusive.\n\n");
        print_help();
        return 1;
    }

    if (xpriv_set && passphrase_set) {
        printf("Error: --passphrase cannot be used with --xpriv.\n\n");
        print_help();
        return 1;
    }

    struct ext_key master_key;

    if (xpriv_set) {
        printf("xpriv: %s\n", xpriv);
        if (bip32_key_from_base58(xpriv, &master_key) != WALLY_OK) {
            printf("Error: Invalid xpriv.\n");
            return 1;
        }
    } else {
        printf("Mnemonic: %s\n", mnemonic);

        if (passphrase_set) {
            printf("Passphrase: %s\n", passphrase);
        }

        const int wally_res = bip39_mnemonic_validate(NULL, mnemonic);
        if (wally_res != WALLY_OK) {
            printf("Error: Invalid mnemonic %s\n\n", mnemonic);
            print_help();
            return 1;
        }

        unsigned char seed[BIP39_SEED_LEN_512];
        const size_t seed_len = sizeof(seed);

        if (bip39_mnemonic_to_seed(mnemonic, passphrase, seed, seed_len, NULL) != WALLY_OK) {
            printf("Error: Failed to convert mnemonic to seed.\n");
            return 1;
        }

        if (bip32_key_from_seed(seed, seed_len, BIP32_VER_MAIN_PRIVATE, 0, &master_key) != WALLY_OK) {
            printf("Error: Failed to generate BIP32 key from seed.\n");
            return 1;
        }
    }

    printf("Index: %d\n", index);
    printf("Key bits: %d\n", key_bits);

    uint8_t entropy[64];
    size_t written = 0;

    const int result = bip85_get_rsa_entropy(&master_key, key_bits, index, entropy, sizeof(entropy), &written);
    if (result != WALLY_OK && written == sizeof(entropy)) {
        printf("Error: Failed to generate RSA entropy from BIP32 key (invalid key_bits or index?).\n");
        return 1;
    }
    char* hex_str = NULL;
    if (wally_hex_from_bytes(entropy, sizeof(entropy), &hex_str) == WALLY_OK) {
        printf("Entropy (hex): %s\n", hex_str);
    }

    wally_free_string(hex_str);
    print_rsa_key(key_bits, entropy, sizeof(entropy));
    return 0;
}
