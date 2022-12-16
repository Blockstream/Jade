idf_component_register(
    SRCS "miner.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES libwally-core esp_timer
)
