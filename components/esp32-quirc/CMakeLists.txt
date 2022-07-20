idf_component_register(SRC_DIRS "lib" "openmv"
        INCLUDE_DIRS "lib" ".")

target_compile_options(${COMPONENT_LIB} PRIVATE -Ofast)
