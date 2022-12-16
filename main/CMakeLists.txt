if(NOT CONFIG_ESP32_NO_BLOBS)
    set(bledir "ble")
endif()

if(CONFIG_ETH_USE_OPENETH)
    set(qemudir "qemu")
endif()

idf_component_register(SRC_DIRS "."
                                "process"
                                "utils"
                                "ui"
                                "${bledir}"
                                "${qemudir}"
        PRIV_INCLUDE_DIRS "."
                          "${bledir}"
                          "${qemudir}"
        PRIV_REQUIRES assets libwally-core tft libsodium button esp32-rotary-encoder esp32-quirc bootloader_support app_update nvs_flash bt autogenlang cbor esp_netif esp32_bsdiff esp32_deflate nghttp esp32_bc-ur driver mbedtls http_parser esp_hw_support efuse esp_eth miner
        EMBED_FILES ${PROJECT_DIR}/pinserver_public_key.pub)

target_link_libraries(${COMPONENT_TARGET} "-u custom_app_desc")
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DBUILD_ELEMENTS=1")
list(APPEND link_options "-Wl,--wrap=abort")
idf_build_set_property(LINK_OPTIONS "${link_options}" APPEND)
