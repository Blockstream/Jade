idf_component_register(SRC_DIRS "."
        INCLUDE_DIRS "."
                     ${PROJECT_DIR}/build/esp-idf/autogenlang)

add_custom_target(autogenlang ALL python3 ${COMPONENT_DIR}/gen_locale.py
                  BYPRODUCTS ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.h
                             ${PROJECT_DIR}/build/esp-idf/autogenlang/autogen_lang.c)
