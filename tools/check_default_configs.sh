#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    . ${HOME}/esp/esp-idf/export.sh
fi

export IDF_COMPONENT_API_CACHE_EXPIRATION_MINUTES=500
export IDF_COMPONENT_CHECK_NEW_VERSION=0
export IDF_CCACHE_ENABLE=1

rm -fr sdkconfig sdkconfig.defaults build managed_components

idf.py set-target esp32s3
for filename in production/*s3*.defaults configs/*s3*.defaults; do
    rm -fr sdkconfig sdkconfig.defaults
    idf.py -D SDKCONFIG_DEFAULTS="${filename}" reconfigure save-defconfig
    tail -n +4 sdkconfig.defaults | LC_ALL=C sort -o ${filename}
done

idf.py set-target esp32
for filename in production/*.defaults configs/*.defaults; do
    [[ $filename == *"s3"* ]] && continue
    rm -fr sdkconfig sdkconfig.defaults
    idf.py -D SDKCONFIG_DEFAULTS="${filename}" reconfigure save-defconfig
    tail -n +4 sdkconfig.defaults | LC_ALL=C sort -o ${filename}
done
rm -fr sdkconfig sdkconfig.defaults build managed_components
