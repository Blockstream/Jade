#!/bin/bash
set -eo pipefail

CONTAINER_SHARED_DIRECTORY=/docker_data
HOST_SHARED_DIRECTORY=./docker_data
CONFIGS_DIR=./configs
HOST_OUTPUT_DIR=${HOST_SHARED_DIRECTORY}/firmware_binaries
EXCLUDE_CONFIG=("_jade" "_ci" "_qemu" "_noradio" "display")
COMPRESS_OUTPUT=false

if [ "$1" = "-c" ]; then
    COMPRESS_OUTPUT=true
fi

# Create output directory if it doesn't exist
mkdir -p ${HOST_OUTPUT_DIR}

# Function to clean up config name (remove sdkconfig_ prefix and .defaults suffix)
clean_config_name() {
    local config_file=$1
    echo "${config_file}" | sed 's/^sdkconfig_//' | sed 's/\.defaults$//'
}

# Function to build firmware for a specific config
build_firmware() {
    local config_file=$1
    local config_name=$(clean_config_name $(basename ${config_file}))
    
    echo "Building firmware for config: ${config_name}"
    
    # Build binaries inside docker container
    docker compose -f docker-compose.dev.yml exec dev bash -c "
        source ~/esp/esp-idf/export.sh; \
        rm -f sdkconfig; \
        cp ${config_file} sdkconfig.defaults; \
        idf.py build; \
        cp build/bootloader/bootloader.bin ${CONTAINER_SHARED_DIRECTORY}/; \
        cp build/partition_table/partition-table.bin ${CONTAINER_SHARED_DIRECTORY}/; \
        cp build/ota_data_initial.bin ${CONTAINER_SHARED_DIRECTORY}/; \
        cp build/jade.bin ${CONTAINER_SHARED_DIRECTORY}/
    "
    if [ $COMPRESS_OUTPUT ]; then
        zip -j "${HOST_OUTPUT_DIR}"/"${config_name}".zip \
            ${HOST_SHARED_DIRECTORY}/bootloader.bin ${HOST_SHARED_DIRECTORY}/jade.bin \
            ${HOST_SHARED_DIRECTORY}/ota_data_initial.bin ${HOST_SHARED_DIRECTORY}/partition-table.bin
    fi

    mv ${HOST_SHARED_DIRECTORY}/bootloader.bin ${HOST_SHARED_DIRECTORY}/"${config_name}"-bootloader.bin
    mv ${HOST_SHARED_DIRECTORY}/jade.bin ${HOST_SHARED_DIRECTORY}/"${config_name}"-jade.bin
    mv ${HOST_SHARED_DIRECTORY}/ota_data_initial.bin ${HOST_SHARED_DIRECTORY}/"${config_name}"-ota_data_initial.bin
    mv ${HOST_SHARED_DIRECTORY}/partition-table.bin ${HOST_SHARED_DIRECTORY}/"${config_name}"-partition-table.bin
    echo "Firmware built and packaged: ${config_name}.zip"
}

# Start docker image
docker compose -f docker-compose.dev.yml up -d

# Build firmware for each configuration
for config in "${CONFIGS_DIR}"/sdkconfig*.defaults; do
    if [[ -f "$config" ]]; then
        # Check if config should be excluded
        config_basename=$(basename "$config")
        should_exclude=false
        
        for exclude_pattern in "${EXCLUDE_CONFIG[@]}"; do
            if [[ "$config_basename" == *"$exclude_pattern"* ]]; then
                should_exclude=true
                break
            fi
        done
        
        if [[ "$should_exclude" == false ]]; then
            build_firmware "$config"
        else
            echo "Skipping excluded config: $config_basename"
        fi
    fi
done


echo "All firmware binaries built successfully!"
