cmake_minimum_required(VERSION 3.10)

project(bip85_rsa_key_gen VERSION 1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -flto")
set(CMAKE_C_FLAGS_DEBUG "-O2 -march=native")
set(CMAKE_EXE_LINKER_FLAGS "-flto")

if(NOT DEFINED ENV{IDF_PATH})
    message(FATAL_ERROR "IDF_PATH environment variable is not set. Please set it to continue.")
endif()

set(IDF_PATH $ENV{IDF_PATH})

set (LIBWALLY_ROOT_DIR ../../components/libwally-core)

set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable building mbedtls programs")
set(ENABLE_TESTING OFF CACHE BOOL "Disable building mbedtls tests")

set (MBEDTLS_ROOT_DIR ${IDF_PATH}/components/mbedtls/mbedtls ${CMAKE_BINARY_DIR}/mbedtls_build)

add_subdirectory(${MBEDTLS_ROOT_DIR})

set(WALLY_PRIV_INCLUDE_FILES
                       ${LIBWALLY_ROOT_DIR}/
                       ${LIBWALLY_ROOT_DIR}/upstream
                       ${LIBWALLY_ROOT_DIR}/upstream/src
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ccan
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/include
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/ecdh
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/ecdsa_adaptor
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/ecdsa_s2c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/extrakeys
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/generator
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/musig
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/rangeproof
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/recovery
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/schnorrsig
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/surjection
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/modules/whitelist
)

set(WALLY_SOURCE_FILES
                       ${LIBWALLY_ROOT_DIR}/upstream/src/address.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/aes.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/anti_exfil.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/base_58.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/base_64.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/bech32.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/bip32.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/bip38.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/bip39.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/bip85.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/blech32.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/descriptor.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ecdh.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/elements.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/hex_.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/hmac.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/internal.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/map.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/mnemonic.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/pbkdf2.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/psbt.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/pullpush.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/script.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/scrypt.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/sign.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/symmetric.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/transaction.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/wif.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/wordlist.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ccan/ccan/base64/base64.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ccan/ccan/crypto/ripemd160/ripemd160.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ccan/ccan/crypto/sha256/sha256.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ccan/ccan/crypto/sha512/sha512.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/ccan/ccan/str/hex/hex.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/secp256k1.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/precomputed_ecmult.c
                       ${LIBWALLY_ROOT_DIR}/upstream/src/secp256k1/src/precomputed_ecmult_gen.c
)

add_executable(bip85_rsa_key_gen main.c ../../main/utils/shake256.c)

target_compile_definitions(bip85_rsa_key_gen PRIVATE
    "-DNDEBUG=1"
    "-DBUILD_ELEMENTS=1"
    "-DBUILD_MINIMAL=1"
    "-DECMULT_WINDOW_SIZE=8"
    "-DENABLE_MODULE_ECDH=1"
    "-DENABLE_MODULE_ECDSA_S2C=1"
    "-DENABLE_MODULE_EXTRAKEYS=1"
    "-DENABLE_MODULE_GENERATOR=1"
    "-DENABLE_MODULE_RANGEPROOF=1"
    "-DENABLE_MODULE_WHITELIST=1"
    "-DENABLE_MODULE_RECOVERY=1"
    "-DENABLE_MODULE_SCHNORRSIG=1"
    "-DENABLE_MODULE_SURJECTIONPROOF=1"
)

target_sources(bip85_rsa_key_gen PRIVATE ${WALLY_SOURCE_FILES})
target_include_directories(bip85_rsa_key_gen PRIVATE ${WALLY_PRIV_INCLUDE_FILES} ../../main)
target_include_directories(bip85_rsa_key_gen PUBLIC ${MBEDTLS_ROOT_DIR}/include ${LIBWALLY_ROOT_DIR}/upstream/include)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

install(TARGETS bip85_rsa_key_gen DESTINATION bin)

target_compile_options(bip85_rsa_key_gen PRIVATE -fno-exceptions -Wundef -march=native)
target_link_libraries(bip85_rsa_key_gen PRIVATE mbedcrypto)
target_link_options(bip85_rsa_key_gen PRIVATE -Wl,-z,relro,-z,now)

add_custom_target(run
    COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bip85_rsa_key_gen
    DEPENDS bip85_rsa_key_gen
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)
