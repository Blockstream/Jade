idf_component_register(SRCS
                       "upstream/src/amalgamation/combined.c"
                       INCLUDE_DIRS
                       "upstream/include"
                       PRIV_INCLUDE_DIRS
                       "."
                       "upstream"
                       "upstream/src"
                       "upstream/src/ccan"
                       "upstream/src/secp256k1"
                       "upstream/src/secp256k1/src"
                       "upstream/src/secp256k1/include"
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
    upstream/src/amalgamation/combined.c
    PROPERTIES COMPILE_FLAGS
    "-Wno-nonnull-compare -Wno-unused-function -Wno-error=maybe-uninitialized -Wno-type-limits -Wno-error=array-parameter"
    )

# fortify/performance flags
target_compile_definitions(${COMPONENT_TARGET} PRIVATE NDEBUG=1)
target_compile_options(${COMPONENT_TARGET} PRIVATE "-fstack-protector-strong")
target_link_options(${COMPONENT_TARGET} PRIVATE -Wl,-z,relro -Wl,-z,now)
target_compile_definitions(${COMPONENT_TARGET} PRIVATE _FORTIFY_SOURCE=2)

target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DBUILD_ELEMENTS=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DBUILD_MINIMAL=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DHAVE_MBEDTLS_SHA256_H")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DHAVE_MBEDTLS_SHA512_H")

# libsecp flags
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DECMULT_WINDOW_SIZE=8")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_ECDH=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_ECDSA_S2C=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_EXTRAKEYS=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_GENERATOR=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_RANGEPROOF=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_RECOVERY=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_SCHNORRSIG=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_SURJECTIONPROOF=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DENABLE_MODULE_WHITELIST=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DHAVE_BUILTIN_POPCOUNT=1")

add_custom_command(TARGET ${COMPONENT_LIB}
                   POST_BUILD
                   COMMAND ${CMAKE_OBJCOPY} --strip-unneeded -W sha256_init -W sha256_done -W sha512_init -W sha512_done ${CMAKE_CURRENT_BINARY_DIR}/liblibwally-core.a)
