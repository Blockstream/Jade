idf_component_register(SRC_DIRS "."
        INCLUDE_DIRS "." "${CMAKE_CURRENT_BINARY_DIR}")

add_custom_command(OUTPUT ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.c
                          ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.h
     COMMAND python3 ${COMPONENT_DIR}/gen_locale.py
     DEPENDS ${COMPONENT_DIR}/gen_locale.py
     VERBATIM)

add_custom_target(gen_locale_files
                  DEPENDS ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.c
                          ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.h)
add_dependencies(${COMPONENT_LIB} gen_locale_files)

set_property(DIRECTORY "${COMPONENT_DIR}" APPEND PROPERTY
     ADDITIONAL_MAKE_CLEAN_FILES ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.c
                                 ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.h)
