cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS bootloader_components/bootloader_support)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(DEPENDENCIES_LOCK dependencies.lock.${IDF_TARGET})
project(jade)
