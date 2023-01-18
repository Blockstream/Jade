if(CONFIG_BT_ENABLED)
    set(bledir "ble")
endif()

if(CONFIG_ETH_USE_OPENETH)
    set(qemudir "qemu")
    if (CONFIG_HAS_CAMERA)
        set(qemu_display_file ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
    endif()
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
        PRIV_REQUIRES assets libwally-core tft libsodium button esp32-rotary-encoder esp32-quirc bootloader_support app_update nvs_flash bt autogenlang cbor esp_netif esp32_bsdiff esp32_deflate nghttp esp32_bc-ur driver mbedtls http_parser esp_hw_support efuse esp_eth esp_http_server
        EMBED_FILES ${PROJECT_DIR}/pinserver_public_key.pub "${qemu_display_file}")

if(CONFIG_ETH_USE_OPENETH)
    if (CONFIG_HAS_CAMERA)
        add_custom_command(OUTPUT ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz
             COMMAND gzip -k -9 -c ${PROJECT_DIR}/main/qemu/display.html > ${PROJECT_DIR}/build/display.html.gz
             COMMAND gzip -k -9 -c ${PROJECT_DIR}/main/qemu/jade.png > ${PROJECT_DIR}/build/jade.png.gz
             DEPENDS ${PROJECT_DIR}/main/qemu/display.html ${PROJECT_DIR}/main/qemu/jade.png
             VERBATIM)
        add_custom_target(gen_gz_files
                          DEPENDS ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
        add_dependencies(${COMPONENT_LIB} gen_gz_files)

        set_property(DIRECTORY "${COMPONENT_DIR}" APPEND PROPERTY
                ADDITIONAL_MAKE_CLEAN_FILES ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
        list(APPEND link_options "-Wl,--wrap=drawPixel")
        list(APPEND link_options "-Wl,--wrap=TFT_pushColorRep")
        list(APPEND link_options "-Wl,--wrap=esp_camera_init")
        list(APPEND link_options "-Wl,--wrap=esp_camera_deinit")
        list(APPEND link_options "-Wl,--wrap=esp_camera_fb_get")
        list(APPEND link_options "-Wl,--wrap=esp_camera_fb_return")
        list(APPEND link_options "-Wl,--wrap=send_data")
    endif()
endif()

target_link_libraries(${COMPONENT_TARGET} "-u custom_app_desc")
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DBUILD_ELEMENTS=1")
list(APPEND link_options "-Wl,--wrap=abort")
idf_build_set_property(LINK_OPTIONS "${link_options}" APPEND)
