#include <sdkconfig.h>

#include "attestation.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "random.h"
#include "sensitive.h"
#include "utils/malloc_ext.h"

#include <esp_ds.h>
#include <esp_efuse.h>
#include <esp_err.h>
#include <esp_partition.h>

#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include <wally_crypto.h>

#include <string.h>

// NOTE: these two params indicate the same efuse and so must be kept in
// lock-step - KEY0==ID0, KEY0==ID0, etc. [id = fuse-4? undocumented ...]
#define JADE_ATTEST_EFUSE EFUSE_BLK_KEY0
#define JADE_ATTEST_HMAC_EFUSE_ID 0

#ifdef CONFIG_DEBUG_MODE
#define ALLOW_REINITIALISE 1
#endif

#define JADE_ATTEST_CURRENT_VERSION 1
static const char JADE_ATTEST_PARTITION_NAME[] = "attest";

// Data saved to (logically write-once) partition
typedef struct {
    esp_ds_data_t encrypted_ds_params;
    char pubkey_pem[JADE_ATTEST_RSA_PUBKEY_PEM_MAX_LEN];
    uint8_t ext_signature[JADE_ATTEST_RSA_KEY_LEN];
    uint16_t pubkey_pem_len; // strlen
    uint16_t ext_signature_len;
} attestation_data_t;

#define READ_FIELD(dest, length)                                                                                       \
    do {                                                                                                               \
        const esp_err_t rc = esp_partition_read(partition, offset, dest, length);                                      \
        if (rc != ESP_OK) {                                                                                            \
            JADE_LOGE("Failed to read data length %u at offset %u from attestation partition %s at %p: %d", length,    \
                offset, JADE_ATTEST_PARTITION_NAME, partition, rc);                                                    \
            return false;                                                                                              \
        }                                                                                                              \
        offset += length;                                                                                              \
    } while (false)

#define WRITE_FIELD(dest, length)                                                                                      \
    do {                                                                                                               \
        const esp_err_t rc = esp_partition_write(partition, offset, dest, length);                                     \
        if (rc != ESP_OK) {                                                                                            \
            JADE_LOGE("Failed to write data length %u at offset %u to attestation partition %s at %p: %d", length,     \
                offset, JADE_ATTEST_PARTITION_NAME, partition, rc);                                                    \
            return false;                                                                                              \
        }                                                                                                              \
        offset += length;                                                                                              \
    } while (false)

static const esp_partition_t* get_attestation_partition(void)
{
    // Locate partition
    const esp_partition_t* partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_UNDEFINED, JADE_ATTEST_PARTITION_NAME);

    if (!partition) {
        JADE_LOGE("Cannot locate attestation data partition %s", JADE_ATTEST_PARTITION_NAME);
        return NULL;
    }

    JADE_LOGI("Attestation partition found, length: %lu", partition->size);
    return partition;
}

static bool save_attestation_data(const attestation_data_t* attestation_data)
{
    JADE_ASSERT(attestation_data);
    JADE_ASSERT(attestation_data->pubkey_pem[attestation_data->pubkey_pem_len] == '\0');
    JADE_ASSERT(attestation_data->encrypted_ds_params.rsa_length == ESP_DS_RSA_4096);

    JADE_LOGI("Persisting attestation data, length %u", sizeof(attestation_data_t));
    JADE_LOGI("Pubkey len: %u", attestation_data->pubkey_pem_len);

    // Locate partition
    const esp_partition_t* partition = get_attestation_partition();
    if (!partition) {
        return false;
    }

    // Partitions data must be erased before it can be (re-)written
    JADE_ASSERT(esp_partition_erase_range(partition, 0, partition->size) == ESP_OK);

    size_t offset = 0;

    // Version - atm should always be 1
    const int8_t version = JADE_ATTEST_CURRENT_VERSION;
    WRITE_FIELD(&version, sizeof(version));

    // Write the encrypted attestation data struct
    WRITE_FIELD(attestation_data, sizeof(attestation_data_t));

    // Write the hash of the attestation data
    uint8_t hash_calc[SHA256_LEN];
    JADE_WALLY_VERIFY(
        wally_sha256((const uint8_t*)attestation_data, sizeof(attestation_data_t), hash_calc, sizeof(hash_calc)));
    WRITE_FIELD(hash_calc, sizeof(hash_calc));

    // Attestation data written to partition without error
    return true;
}

static bool load_attestation_data(attestation_data_t* attestation_data)
{
    JADE_ASSERT(attestation_data);

    JADE_LOGI("Loading attestation data, length %u", sizeof(attestation_data_t));

    // Locate partition
    const esp_partition_t* partition = get_attestation_partition();
    if (!partition) {
        return false;
    }

    size_t offset = 0;

    // Version - atm should always be 1
    uint8_t version = 0;
    READ_FIELD(&version, sizeof(version));
    JADE_ASSERT(version == JADE_ATTEST_CURRENT_VERSION);

    // Read the encrypted attestation data struct
    READ_FIELD(attestation_data, sizeof(attestation_data_t));

    // Read and verify the hash of the attestation data
    uint8_t hash_read[SHA256_LEN];
    READ_FIELD(hash_read, sizeof(hash_read));

    uint8_t hash_calc[SHA256_LEN];
    JADE_WALLY_VERIFY(
        wally_sha256((const uint8_t*)attestation_data, sizeof(attestation_data_t), hash_calc, sizeof(hash_calc)));

    if (memcmp(hash_read, hash_calc, sizeof(hash_calc))) {
        JADE_LOGE("Attestation data unexpected hash");
        return false;
    }

    if (attestation_data->pubkey_pem[attestation_data->pubkey_pem_len] != '\0'
        || attestation_data->encrypted_ds_params.rsa_length != ESP_DS_RSA_4096
        || !attestation_data->ext_signature_len) {
        JADE_LOGE("Attestation data unexpected values");
        return false;
    }

    // Attestation data read from partition and appears sound
    return true;
}

static bool import_rsa_key(mbedtls_pk_context* pk, const char* pem, const size_t pem_len, const bool is_private_key)
{
    JADE_ASSERT(pk);
    JADE_ASSERT(pem);
    JADE_ASSERT(pem_len);
    JADE_ASSERT(pem[pem_len] == '\0'); // bytes passed to parser must include nul-terminator

    int rc;
    if (is_private_key) {
        JADE_LOGI("Importing RSA private key from pem of length %u", pem_len);
        rc = mbedtls_pk_parse_key(pk, (const uint8_t*)pem, pem_len + 1, NULL, 0, random_mbedtls_cb, NULL);
    } else {
        JADE_LOGI("Importing RSA public key from pem of length %u", pem_len);
        rc = mbedtls_pk_parse_public_key(pk, (const uint8_t*)pem, pem_len + 1);
    }

    if (rc) {
        JADE_LOGE("PEM data parse failed: %d", rc);
        return false;
    }

    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_RSA) {
        JADE_LOGE("Unexpected key type");
        return false;
    }

    JADE_ZERO_VERIFY(mbedtls_rsa_complete(mbedtls_pk_rsa(*pk)));

    JADE_LOGI("Key import complete, length %u bits", mbedtls_pk_get_bitlen(pk));
    return true;
}

static bool verify_signature(mbedtls_pk_context* pk, const uint8_t* data, const size_t data_len,
    const uint8_t* signature, const size_t signature_len)
{
    JADE_ASSERT(pk);
    JADE_ASSERT(data);
    JADE_ASSERT(data_len);
    JADE_ASSERT(signature);
    JADE_ASSERT(signature_len);

    // Hash the data with sha256
    uint8_t signed_hash[SHA256_LEN];
    JADE_WALLY_VERIFY(wally_sha256(data, data_len, signed_hash, sizeof(signed_hash)));

    // Verify the signature
    const int rc = mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, signed_hash, 0, signature, signature_len);
    if (rc) {
        JADE_LOGE("Signature validation failed: %d", rc);
        return false;
    }

    return true;
}

/* Construct a PKCS v1.5 encoding of a hashed message
 *
 * This is used both for signature generation and verification.
 *
 * Parameters:
 * - md_alg:  Identifies the hash algorithm used to generate the given hash;
 *            MBEDTLS_MD_NONE if raw data is signed.
 * - hashlen: Length of hash in case hashlen is MBEDTLS_MD_NONE.
 * - hash:    Buffer containing the hashed message or the raw data.
 * - dst_len: Length of the encoded message.
 * - dst:     Buffer to hold the encoded message.
 *
 * Assumptions:
 * - hash has size hashlen if md_alg == MBEDTLS_MD_NONE.
 * - hash has size corresponding to md_alg if md_alg != MBEDTLS_MD_NONE.
 * - dst points to a buffer of size at least dst_len.
 *
 * NOTE: lifted from components/mbedtls/port/esp_ds/esp_rsa_sign_alt.c
 */
static int rsa_rsassa_pkcs1_v15_encode(
    mbedtls_md_type_t md_alg, unsigned int hashlen, unsigned char* hash, const size_t dst_len, unsigned char* dst)
{
    size_t oid_size = 0;
    size_t nb_pad = dst_len;
    unsigned char* p = dst;
    const char* oid = NULL;

    /* Are we signing hashed or raw data? */
    if (md_alg != MBEDTLS_MD_NONE) {
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_alg);
        if (md_info == NULL)
            return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

        if (mbedtls_oid_get_oid_by_md(md_alg, &oid, &oid_size) != 0)
            return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

        hashlen = mbedtls_md_get_size(md_info);

        /* Double-check that 8 + hashlen + oid_size can be used as a
         * 1-byte ASN.1 length encoding and that there's no overflow. */
        if (8 + hashlen + oid_size >= 0x80 || 10 + hashlen < hashlen || 10 + hashlen + oid_size < 10 + hashlen)
            return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

        /*
         * Static bounds check:
         * - Need 10 bytes for five tag-length pairs.
         *   (Insist on 1-byte length encodings to protect against variants of
         *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
         * - Need hashlen bytes for hash
         * - Need oid_size bytes for hash alg OID.
         */
        if (nb_pad < 10 + hashlen + oid_size)
            return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
        nb_pad -= 10 + hashlen + oid_size;
    } else {
        if (nb_pad < hashlen)
            return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

        nb_pad -= hashlen;
    }

    /* Need space for signature header and padding delimiter (3 bytes),
     * and 8 bytes for the minimal padding */
    if (nb_pad < 3 + 8)
        return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
    nb_pad -= 3;

    /* Now nb_pad is the amount of memory to be filled
     * with padding, and at least 8 bytes long. */

    /* Write signature header and padding */
    *p++ = 0;
    *p++ = MBEDTLS_RSA_SIGN;
    memset(p, 0xFF, nb_pad);
    p += nb_pad;
    *p++ = 0;

    /* Are we signing raw data? */
    if (md_alg == MBEDTLS_MD_NONE) {
        memcpy(p, hash, hashlen);
        return (0);
    }

    /* Signing hashed data, add corresponding ASN.1 structure
     *
     * DigestInfo ::= SEQUENCE {
     *   digestAlgorithm DigestAlgorithmIdentifier,
     *   digest Digest }
     * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
     * Digest ::= OCTET STRING
     *
     * Schematic:
     * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
     *                                 TAG-NULL + LEN [ NULL ] ]
     *                 TAG-OCTET + LEN [ HASH ] ]
     */
    *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
    *p++ = (unsigned char)(0x08 + oid_size + hashlen);
    *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
    *p++ = (unsigned char)(0x04 + oid_size);
    *p++ = MBEDTLS_ASN1_OID;
    *p++ = (unsigned char)oid_size;
    memcpy(p, oid, oid_size);
    p += oid_size;
    *p++ = MBEDTLS_ASN1_NULL;
    *p++ = 0x00;
    *p++ = MBEDTLS_ASN1_OCTET_STRING;
    *p++ = (unsigned char)hashlen;
    memcpy(p, hash, hashlen);
    p += hashlen;

    /* Just a sanity-check, should be automatic
     * after the initial bounds check. */
    if (p != dst + dst_len) {
        mbedtls_platform_zeroize(dst, dst_len);
        return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
    }

    return (0);
}

static void calc_rinv_mprime(const mbedtls_mpi* N, mbedtls_mpi* rinv, uint32_t* mprime)
{
    JADE_ASSERT(N);
    JADE_ASSERT(rinv);
    JADE_ASSERT(mprime);

    mbedtls_mpi tmp, a;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&a);

    JADE_LOGI("Calculating rinv/mprime");

    // tmp = 1 << (key_size * 2) # in bits
    // rinv = tmp % N
    JADE_ZERO_VERIFY(mbedtls_mpi_lset(&tmp, 1));
    JADE_ZERO_VERIFY(mbedtls_mpi_shift_l(&tmp, JADE_ATTEST_RSA_KEY_LEN * 8 * 2));
    JADE_ZERO_VERIFY(mbedtls_mpi_mod_mpi(rinv, &tmp, N));

    // tmp = 1 << 32
    // a = inv_mod(N, 1 << 32)
    JADE_ZERO_VERIFY(mbedtls_mpi_lset(&tmp, 1));
    JADE_ZERO_VERIFY(mbedtls_mpi_shift_l(&tmp, 32));
    JADE_ZERO_VERIFY(mbedtls_mpi_inv_mod(&a, N, &tmp));

    // a32 = a
    uint32_t a32 = 0;
    JADE_ZERO_VERIFY(mbedtls_mpi_write_binary_le(&a, (uint8_t*)&a32, sizeof(uint32_t)));

    // mprime
    *mprime = ((int32_t)a32 * -1) & 0xFFFFFFFF;

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&a);
}

static void reverse_in_place(uint8_t* buf, const size_t len)
{
    JADE_ASSERT(buf);
    JADE_ASSERT(len);

    for (size_t i = 0; i < len / 2; ++i) {
        const int mirror_idx = len - i - 1;
        const uint8_t tmp = buf[i];
        buf[i] = buf[mirror_idx];
        buf[mirror_idx] = tmp;
    }
}

static void rsa_ctx_to_ds_params(mbedtls_rsa_context* rsa, esp_ds_p_data_t* params)
{
    JADE_ASSERT(rsa);
    JADE_ASSERT(params);

    mbedtls_mpi N, D;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    JADE_ZERO_VERIFY(mbedtls_rsa_export(rsa, &N, NULL, NULL, &D, NULL));

    // Get rinv & mprime
    uint32_t mprime = 0;
    mbedtls_mpi rinv;
    mbedtls_mpi_init(&rinv);
    calc_rinv_mprime(&N, &rinv, &mprime);

    // Write to ds params
    JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&D, (uint8_t*)params->Y, sizeof(params->Y)));
    JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&N, (uint8_t*)params->M, sizeof(params->M)));
    JADE_ZERO_VERIFY(mbedtls_mpi_write_binary(&rinv, (uint8_t*)params->Rb, sizeof(params->Rb)));

    // Convert to little-endian
    reverse_in_place((uint8_t*)params->Y, JADE_ATTEST_RSA_KEY_LEN);
    reverse_in_place((uint8_t*)params->M, JADE_ATTEST_RSA_KEY_LEN);
    reverse_in_place((uint8_t*)params->Rb, JADE_ATTEST_RSA_KEY_LEN);

    params->M_prime = mprime;
    params->length = ESP_DS_RSA_4096;

    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&rinv);
}

bool attestation_initialised(void)
{
    // Check efuse
    const esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(JADE_ATTEST_EFUSE);
    if (purpose != ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE) {
        return false;
    }

    // Check saved attestation data
    attestation_data_t attestation_data = {};
    if (!load_attestation_data(&attestation_data)
        || attestation_data.encrypted_ds_params.rsa_length != ESP_DS_RSA_4096) {
        return false;
    }

    return true;
}

bool attestation_initialise(const char* privkey_pem, const size_t privkey_pem_len, const char* ext_pubkey_pem,
    const size_t ext_pubkey_pem_len, const uint8_t* ext_signature, const size_t ext_signature_len)
{
    JADE_ASSERT(privkey_pem);
    JADE_ASSERT(privkey_pem_len);
    JADE_ASSERT(privkey_pem[privkey_pem_len] == '\0');
    JADE_ASSERT(ext_pubkey_pem);
    JADE_ASSERT(ext_pubkey_pem_len);
    JADE_ASSERT(ext_pubkey_pem[ext_pubkey_pem_len] == '\0');
    JADE_ASSERT(ext_signature);
    JADE_ASSERT(ext_signature_len);

    // Check to see if relevant efuse already written
    const esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(JADE_ATTEST_EFUSE);
    if (purpose == ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE) {
        // Pubkey/hmac efuse already written
        JADE_LOGE("Attestation initialisation attempted but efuse/parameters already initialised");
#ifdef ALLOW_REINITIALISE
        JADE_LOGE("Reinitialising enabled, continuing ...");
    } else
#else
        return false;
    }
#endif

        if (purpose != ESP_EFUSE_KEY_PURPOSE_USER) {
        // Appears to be used for some other purpose!
        JADE_LOGE("Attestation efuse %u already has unexpected purpose %u!", JADE_ATTEST_EFUSE, purpose);
        return false;
    }

    JADE_LOGI("Initialising attestation parameters");
    attestation_data_t attestation_data = {};
    bool retval = false;

    // Random iv and hmac key
    uint8_t iv[16];
    get_random(iv, sizeof(iv));

    uint8_t hmac_key[32];
    SENSITIVE_PUSH(hmac_key, sizeof(hmac_key));
    get_random(hmac_key, sizeof(hmac_key));

#ifdef ALLOW_REINITIALISE
    // Use fixed key data for dev period
    const uint8_t key_data[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    for (size_t i = 0; i < sizeof(hmac_key); ++i) {
        hmac_key[i] = key_data[i];
    }
#endif

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    const bool is_private_key = true;

    // Import RSA private key - expected 4096-bit key
    if (!import_rsa_key(&pk, privkey_pem, privkey_pem_len, is_private_key)
        || mbedtls_pk_get_bitlen(&pk) != (JADE_ATTEST_RSA_KEY_LEN * 8)) {
        JADE_LOGE("Failed to import valid RSA private key of expected length");
        goto cleanup;
    }

    // Convert the private key data to (cleartext) ds params
    esp_ds_p_data_t params = {};
    SENSITIVE_PUSH(&params, sizeof(params));
    rsa_ctx_to_ds_params(mbedtls_pk_rsa(pk), &params);

    // Encrypt RSA params using hmac key into the attestation data
    JADE_ZERO_VERIFY(esp_ds_encrypt_params(&attestation_data.encrypted_ds_params, iv, &params, hmac_key));
    SENSITIVE_POP(&params);

    // Generate the related pubkey pem directly into the attestation data
    const int rc
        = mbedtls_pk_write_pubkey_pem(&pk, (uint8_t*)attestation_data.pubkey_pem, sizeof(attestation_data.pubkey_pem));
    if (rc) {
        JADE_LOGE("Failed to extract rsa pubkey: %d", rc);
        goto cleanup;
    }
    attestation_data.pubkey_pem_len = strlen(attestation_data.pubkey_pem);

    // Import RSA public key for external authority and check signature over signer pubkey
    // If all good, copy that signature into the attestation data
    mbedtls_pk_free(&pk);
    if (!import_rsa_key(&pk, ext_pubkey_pem, ext_pubkey_pem_len, !is_private_key)) {
        JADE_LOGE("Failed to import valid RSA public (external authority) key");
        goto cleanup;
    }
    if (!verify_signature(&pk, (const uint8_t*)attestation_data.pubkey_pem, attestation_data.pubkey_pem_len,
            ext_signature, ext_signature_len)) {
        JADE_LOGE("Failed to validate external signature over signer public key");
        goto cleanup;
    }
    memcpy(attestation_data.ext_signature, ext_signature, ext_signature_len);
    attestation_data.ext_signature_len = ext_signature_len;

    // Persist the new encrypted signing key params
    if (!save_attestation_data(&attestation_data)) {
        JADE_LOGE("Failed to persist attestation data");
        goto cleanup;
    }

    // Immediately load it back, to check the saving/reloading works as expected
    attestation_data_t* const reloaded_data = JADE_MALLOC(sizeof(attestation_data_t));
    if (!load_attestation_data(reloaded_data) || memcmp(&attestation_data, reloaded_data, sizeof(attestation_data_t))) {
        JADE_LOGE("Failed to reload persisted attestation data as expected");
        free(reloaded_data);
        goto cleanup;
    }
    free(reloaded_data);

    // Only burn the hmac key into the efuse when the above has all succeeded
    JADE_LOGW("Burning attestation hmac_key into efuse %u", JADE_ATTEST_HMAC_EFUSE_ID);
    const esp_err_t err = esp_efuse_write_key(
        JADE_ATTEST_EFUSE, ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, hmac_key, sizeof(hmac_key));

    if (err != ESP_OK) {
#ifdef ALLOW_REINITIALISE
        if (err == ESP_ERR_INVALID_STATE
            && esp_efuse_get_key_purpose(JADE_ATTEST_EFUSE) == ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE) {
            JADE_LOGW("eFuse ds key write failed as already written - ignoring");
        } else {
            JADE_LOGE("eFuse ds key write failed: %d", err);
            return false;
        }
#else
        JADE_LOGE("eFuse ds key write failed: %d", err);
        return false;
#endif
    }

    // All good
    JADE_LOGI("Attestation parameters initialised");
    retval = true;

cleanup:
    SENSITIVE_POP(hmac_key);
    mbedtls_pk_free(&pk);
    return retval;
}

bool attestation_sign_challenge(const uint8_t* challenge, const size_t challenge_len, uint8_t* signature,
    const size_t signature_len, char* pubkey_pem, const size_t pubkey_pem_len, size_t* pem_written,
    uint8_t* ext_signature, const size_t ext_signature_len, size_t* ext_sig_written)
{
    JADE_ASSERT(challenge);
    JADE_ASSERT(challenge_len);
    JADE_ASSERT(signature);
    JADE_ASSERT(signature_len == JADE_ATTEST_RSA_KEY_LEN);
    JADE_ASSERT(pubkey_pem);
    JADE_ASSERT(pubkey_pem_len >= JADE_ATTEST_RSA_PUBKEY_PEM_MAX_LEN);
    JADE_INIT_OUT_SIZE(pem_written);
    JADE_ASSERT(ext_signature);
    JADE_ASSERT(ext_signature_len);
    JADE_INIT_OUT_SIZE(ext_sig_written);

    // Check to see if relevant efuse already written
    const esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(JADE_ATTEST_EFUSE);

    if (purpose == ESP_EFUSE_KEY_PURPOSE_USER) {
        // Pubkey/hmac efuse not yet written
        JADE_LOGE("Attestation attempted but efuse/parameters not initialised");
        return false;
    }
    if (purpose != ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE) {
        // Appears to be used for some other purpose!
        JADE_LOGE("Attestation efuse %u has unexpected purpose %u!", JADE_ATTEST_EFUSE, purpose);
        return false;
    }

    // Load attestation data
    attestation_data_t attestation_data = {};
    if (!load_attestation_data(&attestation_data)
        || attestation_data.encrypted_ds_params.rsa_length != ESP_DS_RSA_4096) {
        JADE_LOGE("Failed to load attestation data");
        return false;
    }

    // Hash the challenge
    JADE_LOGI("Preparing signing data");
    uint8_t challenge_hash[SHA256_LEN];
    JADE_WALLY_VERIFY(wally_sha256(challenge, challenge_len, challenge_hash, sizeof(challenge_hash)));

    // Pad the hash
    uint8_t padded_hashed_challenge[JADE_ATTEST_RSA_KEY_LEN];
    JADE_ZERO_VERIFY(rsa_rsassa_pkcs1_v15_encode(
        MBEDTLS_MD_SHA256, 0, challenge_hash, sizeof(padded_hashed_challenge), padded_hashed_challenge));

    // Reverse the data to little-endian
    reverse_in_place(padded_hashed_challenge, sizeof(padded_hashed_challenge));

    // Make the signature with the encrypted rsa key using the ds component
    JADE_LOGI("Invoking hardware signing");
    JADE_ASSERT(signature_len == (attestation_data.encrypted_ds_params.rsa_length + 1) * 4);
    const esp_err_t rc = esp_ds_sign(
        padded_hashed_challenge, &attestation_data.encrypted_ds_params, JADE_ATTEST_HMAC_EFUSE_ID, signature);
    if (rc != ESP_OK) {
        JADE_LOGE("esp_ds_sign() failed: %d", rc);
        return false;
    }

    // Reverse signature to big-endian
    reverse_in_place(signature, signature_len);

    // Copy pubkey pem and external signature to output params
    JADE_ASSERT(pubkey_pem_len > attestation_data.pubkey_pem_len);
    JADE_ASSERT(ext_signature_len >= attestation_data.ext_signature_len);
    JADE_ASSERT(attestation_data.pubkey_pem[attestation_data.pubkey_pem_len] == '\0');
    strcpy(pubkey_pem, attestation_data.pubkey_pem);
    *pem_written = attestation_data.pubkey_pem_len; // strlen
    memcpy(ext_signature, attestation_data.ext_signature, attestation_data.ext_signature_len);
    *ext_sig_written = attestation_data.ext_signature_len;

    return true;
}

bool attestation_verify(const uint8_t* challenge, const size_t challenge_len, const char* pubkey_pem,
    const size_t pubkey_pem_len, const uint8_t* signature, const size_t signature_len, const char* ext_pubkey_pem,
    const size_t ext_pubkey_pem_len, const uint8_t* ext_signature, const size_t ext_signature_len)
{
    JADE_ASSERT(challenge);
    JADE_ASSERT(challenge_len);
    JADE_ASSERT(pubkey_pem);
    JADE_ASSERT(pubkey_pem_len);
    JADE_ASSERT(pubkey_pem[pubkey_pem_len] == '\0');
    JADE_ASSERT(signature);
    JADE_ASSERT(signature_len == JADE_ATTEST_RSA_KEY_LEN);
    JADE_ASSERT(ext_pubkey_pem);
    JADE_ASSERT(ext_pubkey_pem_len);
    JADE_ASSERT(ext_pubkey_pem[ext_pubkey_pem_len] == '\0');
    JADE_ASSERT(ext_signature);
    JADE_ASSERT(ext_signature_len);

    bool retval = false;

    // Import pubkeys
    const bool is_private_key = false;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Import RSA public key for signer and check signature over challenge data
    if (!import_rsa_key(&pk, pubkey_pem, pubkey_pem_len, is_private_key)) {
        JADE_LOGE("Failed to import valid RSA (signer) public key");
        goto cleanup;
    }
    if (!verify_signature(&pk, challenge, challenge_len, signature, signature_len)) {
        JADE_LOGE("Failed to validate external signature over signer public key");
        goto cleanup;
    }

    // Import RSA public key for external authority and check signature over signer pubkey
    mbedtls_pk_free(&pk);
    if (!import_rsa_key(&pk, ext_pubkey_pem, ext_pubkey_pem_len, is_private_key)) {
        JADE_LOGE("Failed to import valid RSA public (external authority) key");
        goto cleanup;
    }
    if (!verify_signature(&pk, (const uint8_t*)pubkey_pem, pubkey_pem_len, ext_signature, ext_signature_len)) {
        JADE_LOGE("Failed to validate external signature over signer public key");
        goto cleanup;
    }

    // All good
    retval = true;

cleanup:
    mbedtls_pk_free(&pk);
    return retval;
}
