#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    . ${HOME}/esp/esp-idf/export.sh
fi

for filename in production/*.defaults configs/*.defaults; do
    rm -fr sdkconfig sdkconfig.defaults build

    if [[ $filename == *"s3"* ]]; then
        esp_variant=esp32s3
    else
        esp_variant=esp32
    fi

    idf.py -D SDKCONFIG_DEFAULTS="${filename}" set-target ${esp_variant} reconfigure save-defconfig
    tail -n +4 sdkconfig.defaults > ${filename}
done
rm -fr sdkconfig sdkconfig.defaults build
