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
        PRIV_REQUIRES assets libwally-core tft libsodium button esp32-rotary-encoder esp32-camera esp32-quirc bootloader_support app_update nvs_flash bt autogenlang cbor esp_netif
        EMBED_TXTFILES ${PROJECT_DIR}/jade_services_certificate.pem
        EMBED_FILES ${PROJECT_DIR}/pinserver_public_key.pub)

target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DBUILD_ELEMENTS=1")
