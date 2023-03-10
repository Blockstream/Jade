idf_component_register(SRCS
                       "upstream/src/address.c"
                       "upstream/src/aes.c"
                       "upstream/src/anti_exfil.c"
                       "upstream/src/base58.c"
                       "upstream/src/base64.c"
                       "upstream/src/bech32.c"
                       "upstream/src/bip32.c"
                       "upstream/src/bip38.c"
                       "upstream/src/bip39.c"
                       "upstream/src/blech32.c"
                       "upstream/src/ecdh.c"
                       "upstream/src/elements.c"
                       "upstream/src/hex.c"
                       "upstream/src/hmac.c"
                       "upstream/src/internal.c"
                       "upstream/src/map.c"
                       "upstream/src/mnemonic.c"
                       "upstream/src/pbkdf2.c"
                       "upstream/src/psbt.c"
                       "upstream/src/pullpush.c"
                       "upstream/src/script.c"
                       "upstream/src/scrypt.c"
                       "upstream/src/sign.c"
                       "upstream/src/symmetric.c"
                       "upstream/src/transaction.c"
                       "upstream/src/wif.c"
                       "upstream/src/wordlist.c"
                       "upstream/src/ccan/ccan/base64/base64.c"
                       "upstream/src/ccan/ccan/crypto/ripemd160/ripemd160.c"
                       "upstream/src/ccan/ccan/crypto/sha256/sha256.c"
                       "upstream/src/ccan/ccan/crypto/sha512/sha512.c"
                       "upstream/src/ccan/ccan/str/hex/hex.c"
                       "upstream/src/secp256k1/src/secp256k1.c"
                       "upstream/src/secp256k1/src/precomputed_ecmult.c"
                       "upstream/src/secp256k1/src/precomputed_ecmult_gen.c"
                       INCLUDE_DIRS
                       "upstream/include"
                       PRIV_INCLUDE_DIRS
                       "."
                       "upstream"
                       "upstream/src"
                       "upstream/src/ccan"
                       "upstream/src/secp256k1"
                       "upstream/src/secp256k1/src"
                       "upstream/src/secp256k1/src/modules/ecdh"
                       "upstream/src/secp256k1/src/modules/ecdsa_adaptor"
                       "upstream/src/secp256k1/src/modules/ecdsa_s2c"
                       "upstream/src/secp256k1/src/modules/extrakeys"
                       "upstream/src/secp256k1/src/modules/generator"
                       "upstream/src/secp256k1/src/modules/musig"
                       "upstream/src/secp256k1/src/modules/rangeproof"
                       "upstream/src/secp256k1/src/modules/recovery"
                       "upstream/src/secp256k1/src/modules/schnorrsig"
                       "upstream/src/secp256k1/src/modules/surjection"
                       "upstream/src/secp256k1/src/modules/whitelist"
                       PRIV_REQUIRES mbedtls)

set_source_files_properties(
    upstream/src/secp256k1/src/secp256k1.c
    upstream/src/secp256k1/src/precomputed_ecmult.c
    upstream/src/secp256k1/src/precomputed_ecmult_gen.c
    upstream/src/secp256k1/src/modules/rangeproof/rangeproof_impl.h
    upstream/src/bip32.c
    upstream/src/bip38.c
    upstream/src/ccan/ccan/base64/base64.c
    upstream/src/psbt.c
    upstream/src/sign.c
    upstream/src/transaction.c
    PROPERTIES COMPILE_FLAGS
    "-Wno-nonnull-compare -Wno-unused-function -Wno-error=maybe-uninitialized -Wno-type-limits"
    )
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DHAVE_CONFIG_H")
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DBUILD_ELEMENTS=1")
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DBUILD_MINIMAL=1")
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DHAVE_MBEDTLS_SHA256_H")
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DHAVE_MBEDTLS_SHA512_H")

add_custom_command(TARGET ${COMPONENT_LIB}
                   POST_BUILD
                   COMMAND ${CMAKE_OBJCOPY} --strip-unneeded -W sha256_init -W sha256_done -W sha512_init -W sha512_done ${CMAKE_CURRENT_BINARY_DIR}/liblibwally-core.a)
