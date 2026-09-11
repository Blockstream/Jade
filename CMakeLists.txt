cmake_minimum_required(VERSION 3.16)
if(DEFINED ESP_PLATFORM AND ESP_PLATFORM EQUAL 1)
    set(EXTRA_COMPONENT_DIRS bootloader_components/bootloader_support)
    # Jade does its own payload CBOR (TinyCBOR) - only the UR transport
    # layer of the cUR component is needed
    set(UR_ENVELOPE_ONLY ON CACHE BOOL "" FORCE)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    idf_build_set_property(DEPENDENCIES_LOCK dependencies.lock.${IDF_TARGET})
    project(jade)
else()
    add_subdirectory(libjade)
endif()
