file(GLOB SOURCE_FILES "*.c" "*.h")

idf_component_register(SRCS ${SOURCE_FILES}
                    INCLUDE_DIRS "."
)
