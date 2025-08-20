cmake_minimum_required(VERSION 3.16) # same we use in idf
project(libjade C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build (Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize)" FORCE)
  message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode (default)")
else()
  message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode (user provided or cached)")
endif()

if(DEFINED ENV{IDF_PATH})
    set(IDF_PATH $ENV{IDF_PATH})
    message(STATUS "Using IDF_PATH from environment: ${IDF_PATH}")
else()
    message(FATAL_ERROR "IDF_PATH is not defined. Please set the IDF_PATH environment variable.")
endif()

find_package(Threads REQUIRED)
set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "Build position-independent code" FORCE)

set(mbedtls_targets mbedtls mbedcrypto mbedx509 everest p256m)
set(ENABLE_TESTING CACHE BOOL OFF)
set(ENABLE_PROGRAMS CACHE BOOL OFF)
set(GEN_FILES CACHE BOOL OFF)
add_subdirectory(${IDF_PATH}/components/mbedtls/mbedtls
                 ${CMAKE_CURRENT_BINARY_DIR}/mbedtls)

set(CBOR_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../managed_components/espressif__cbor/tinycbor/src")
file(GLOB CBOR_SOURCES "${CBOR_SOURCE_DIR}/*.c")
add_library(cbor_target STATIC ${CBOR_SOURCES})
target_include_directories(cbor_target PUBLIC "${CBOR_SOURCE_DIR}")
set(CBOR_INCLUDE_DIR "${CBOR_SOURCE_DIR}")
set(ESP_MOCKED "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Note -DVERIFY enables (expensive) libsecp256k1 verification
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb3 -DVERIFY -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -fstack-clash-protection")

# FIXME: revisit what flags we want in release/production
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

if(CMAKE_BUILD_TYPE STREQUAL "Sanitize")
    add_compile_options(-O1 -ggdb -fsanitize=address -fsanitize=undefined -fsanitize=alignment -fsanitize-address-use-after-scope -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address -fsanitize=undefined -fsanitize=alignment -fsanitize-address-use-after-scope -fno-sanitize-recover=all)
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

# for consistency with the Jade build - we can change if needed
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")

set(COMMON_INCLUDES
  ${CBOR_INCLUDE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../main
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core/upstream/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/assets
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/esp32_bsdiff
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/esp32-quirc
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/esp32-quirc/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core/upstream
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core/upstream/src
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core/upstream/src/ccan
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core
  ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core/upstream/src/secp256k1/include
  ${IDF_PATH}/components/http_parser
)

set(COMMON_SRC
  libjade.c
  ${IDF_PATH}/components/http_parser/http_parser.c
)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../components/esp32_bc-ur
                 ${CMAKE_CURRENT_BINARY_DIR}/bcur)
target_include_directories(bcur PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core/upstream/include)
target_link_libraries(bcur PRIVATE mbedcrypto)

# libjade.so
add_library(jade SHARED ${COMMON_SRC})
target_link_libraries(jade PRIVATE m z bcur cbor_target mbedtls mbedcrypto mbedx509)
target_include_directories(jade PRIVATE ${COMMON_INCLUDES})

set_source_files_properties(libjade.c PROPERTIES COMPILE_OPTIONS
  "-Wall;-W;-Wno-format;-Wno-unused-function;-Wno-unused-parameter;-Wno-sign-compare;-Wno-missing-field-initializers;-Wno-narrowing")
target_compile_definitions(jade PRIVATE LIBJADE_BUILD)

# libjade.a
add_library(jade_static STATIC ${COMMON_SRC})
target_link_libraries(jade_static PRIVATE m z mbedtls mbedcrypto mbedx509 bcur)
target_include_directories(jade_static PRIVATE ${COMMON_INCLUDES})
target_compile_definitions(jade_static PRIVATE LIBJADE_BUILD)

add_executable(libjade_daemon daemon.c)
target_link_libraries(libjade_daemon PRIVATE jade_static bcur cbor_target m z mbedtls mbedcrypto mbedx509 Threads::Threads)
target_include_directories(libjade_daemon PRIVATE ${COMMON_INCLUDES})

# Assets
set(ASSETS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../components/assets)

add_custom_command(OUTPUT asset_data.inc
    COMMAND python3 ${ASSETS_DIR}/gen_assets.py ${ASSETS_DIR}/asset_data.json ${CMAKE_CURRENT_BINARY_DIR}/asset_data.inc
    DEPENDS ${ASSETS_DIR}/gen_assets.py ${ASSETS_DIR}/asset_data.json
    VERBATIM)

add_custom_command(OUTPUT asset_data_testnet.inc
    COMMAND python3 ${ASSETS_DIR}/gen_assets.py ${ASSETS_DIR}/asset_data_testnet.json ${CMAKE_CURRENT_BINARY_DIR}/asset_data_testnet.inc
    DEPENDS ${ASSETS_DIR}/gen_assets.py ${ASSETS_DIR}/asset_data_testnet.json
    VERBATIM)

add_custom_target(asset_data DEPENDS asset_data.inc asset_data_testnet.inc)
add_dependencies(jade asset_data)
add_dependencies(jade_static asset_data)
