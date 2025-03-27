if(CONFIG_BT_ENABLED)
    set(bledir "ble")
endif()

if(CONFIG_ETH_USE_OPENETH)
    set(qemudir "qemu")
    if (CONFIG_HAS_CAMERA)
        set(qemu_display_file ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
    endif()
endif()

if (CONFIG_BOARD_TYPE_JADE OR CONFIG_BOARD_TYPE_JADE_V1_1 OR CONFIG_BOARD_TYPE_JADE_V2)
    list(APPEND logo_files ${PROJECT_DIR}/logo/splash.bin.gz ${PROJECT_DIR}/logo/ce.bin.gz ${PROJECT_DIR}/logo/fcc.bin.gz ${PROJECT_DIR}/logo/weee.bin.gz)
endif()

if (CONFIG_BOARD_TYPE_JADE_V1_1 OR CONFIG_BOARD_TYPE_JADE_V2)
    list(APPEND logo_files ${PROJECT_DIR}/logo/telec.bin.gz)
endif()

if (CONFIG_DISPLAY_HEIGHT GREATER_EQUAL 170)
    list(APPEND logo_files ${PROJECT_DIR}/logo/statusbar_large.bin.gz)
else()
    list(APPEND logo_files ${PROJECT_DIR}/logo/statusbar_small.bin.gz)
endif()

if (CONFIG_IDF_TARGET_ESP32S3)
    list(APPEND logo_files ${PROJECT_DIR}/logo/icon_qrguide_vga_large.bin.gz ${PROJECT_DIR}/logo/icon_qrguide_vga_small.bin.gz)
    set(attestdir "attestation")
    set(usbdir "usbhmsc")
else()
    list(APPEND logo_files ${PROJECT_DIR}/logo/icon_qrguide_qvga_large.bin.gz ${PROJECT_DIR}/logo/icon_qrguide_qvga_small.bin.gz)
endif()

idf_component_register(SRC_DIRS "."
                                "process"
                                "utils"
                                "ui"
                                "fonts"
                                "${bledir}"
                                "${qemudir}"
                                "${attestdir}"
                                "${usbdir}"
        PRIV_INCLUDE_DIRS "."
                          "${bledir}"
                          "${qemudir}"
                          "${attestdir}"
                          "${usbdir}"
        PRIV_REQUIRES assets libwally-core libsodium esp32-rotary-encoder esp32-quirc bootloader_support app_update nvs_flash bt autogenlang cbor esp_netif esp32_bsdiff esp32_deflate nghttp esp32_bc-ur driver mbedtls http_parser esp_hw_support efuse esp_eth esp_http_server esp_lcd usb vfs app_trace spi_flash
        EMBED_FILES ${PROJECT_DIR}/pinserver_public_key.pub ${logo_files} ${qemu_display_file})

if(CONFIG_ETH_USE_OPENETH)
    if (CONFIG_HAS_CAMERA)
        add_custom_command(OUTPUT ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz
             COMMAND sed -e "s/DISPLAY_WIDTH/${CONFIG_DISPLAY_WIDTH}/g" -e "s/DISPLAY_HEIGHT/${CONFIG_DISPLAY_HEIGHT}/g" ${PROJECT_DIR}/main/qemu/display.html | gzip -k -9 -c > ${PROJECT_DIR}/build/display.html.gz
             COMMAND gzip -k -9 -c ${PROJECT_DIR}/main/qemu/${CONFIG_DISPLAY_QEMU_IMAGE}.png > ${PROJECT_DIR}/build/jade.png.gz
             DEPENDS ${PROJECT_DIR}/main/qemu/display.html ${PROJECT_DIR}/main/qemu/jade.png
             VERBATIM)

        add_custom_target(gen_gz_files
                          DEPENDS ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)

        add_dependencies(${COMPONENT_LIB} gen_gz_files)

        set_property(DIRECTORY "${COMPONENT_DIR}" APPEND PROPERTY
                ADDITIONAL_MAKE_CLEAN_FILES ${PROJECT_DIR}/build/display.html.gz ${PROJECT_DIR}/build/jade.png.gz)
        list(APPEND link_options "-Wl,--wrap=esp_camera_init")
        list(APPEND link_options "-Wl,--wrap=esp_camera_deinit")
        list(APPEND link_options "-Wl,--wrap=esp_camera_fb_get")
        list(APPEND link_options "-Wl,--wrap=esp_camera_fb_return")
    endif()
endif()

if(CONFIG_AMALGAMATED_BUILD)
    add_compile_definitions(AMALGAMATED_BUILD=1)
endif()

target_link_libraries(${COMPONENT_TARGET} "-u custom_app_desc")
if(CONFIG_APPTRACE_GCOV_ENABLE)
    target_compile_options(${COMPONENT_LIB} PRIVATE --coverage)
endif()
list(APPEND link_options "-Wl,--wrap=abort")
idf_build_set_property(LINK_OPTIONS "${link_options}" APPEND)
