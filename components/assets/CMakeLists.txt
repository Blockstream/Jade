idf_component_register(SRC_DIRS "."
        INCLUDE_DIRS "." "${CMAKE_CURRENT_BINARY_DIR}")

add_custom_command(OUTPUT asset_data.inc
     COMMAND python3 ${COMPONENT_DIR}/gen_assets.py ${COMPONENT_DIR}/asset_data.json ${CMAKE_CURRENT_BINARY_DIR}/asset_data.inc
     DEPENDS ${COMPONENT_DIR}/gen_assets.py ${COMPONENT_DIR}/asset_data.json
     VERBATIM)

add_custom_command(OUTPUT asset_data_testnet.inc
     COMMAND python3 ${COMPONENT_DIR}/gen_assets.py ${COMPONENT_DIR}/asset_data_testnet.json ${CMAKE_CURRENT_BINARY_DIR}/asset_data_testnet.inc
     DEPENDS ${COMPONENT_DIR}/gen_assets.py ${COMPONENT_DIR}/asset_data_testnet.json
     VERBATIM)

add_custom_target(asset_data DEPENDS asset_data.inc asset_data_testnet.inc)
add_dependencies(${COMPONENT_LIB} asset_data)

set_property(DIRECTORY "${COMPONENT_DIR}" APPEND PROPERTY
     ADDITIONAL_MAKE_CLEAN_FILES asset_data.inc asset_data_testnet.inc)
