cmake_minimum_required(VERSION 3.16)
if(DEFINED ESP_PLATFORM AND ESP_PLATFORM EQUAL 1)
    set(EXTRA_COMPONENT_DIRS bootloader_components/bootloader_support)
    # Jade does its own payload CBOR (TinyCBOR) - only the UR transport
    # layer of the cUR component is needed
    set(UR_ENVELOPE_ONLY ON CACHE BOOL "" FORCE)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    idf_build_set_property(DEPENDENCIES_LOCK dependencies.lock.${IDF_TARGET})
    project(jade)
    idf_component_get_property(cbor_component espressif__cbor COMPONENT_LIB)
    target_compile_definitions(${cbor_component} PRIVATE CBOR_PARSER_MAX_RECURSIONS=20)
    # Jade scans a 220x220 crop, which k_quirc would measure the white level
    # over on a 3x3 grid - too coarse to follow a dim corner. Keep in step
    # with libjade/CMakeLists.txt.
    idf_component_get_property(k_quirc_component k_quirc COMPONENT_LIB)
    target_compile_definitions(${k_quirc_component} PRIVATE K_QUIRC_THRESHOLD_GRID=6)
else()
    add_subdirectory(libjade)
endif()
