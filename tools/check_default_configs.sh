#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    . ${HOME}/esp/esp-idf/export.sh
fi

export IDF_COMPONENT_API_CACHE_EXPIRATION_MINUTES=500
export IDF_COMPONENT_CHECK_NEW_VERSION=0
export IDF_CCACHE_ENABLE=1

rm -fr sdkconfig sdkconfig.defaults build managed_components

# Jade v2/v2c (Jade Plus & Jade Core)
idf.py set-target esp32s3
for filename in production/*_jade_v2*.defaults configs/*_jade_v2*.defaults; do
    rm -fr sdkconfig sdkconfig.defaults
    idf.py -D SDKCONFIG_DEFAULTS="${filename}" reconfigure save-defconfig
    tail -n +4 sdkconfig.defaults | LC_ALL=C sort -o ${filename}.tmp
    # add the first line from the original file back if it was a comment
    head -n 1 ${filename} | grep -q '^#' && echo "$(head -n 1 ${filename}; cat ${filename}.tmp)" > ${filename}.tmp
    mv ${filename}.tmp ${filename}
done

# Jade v1.0/v1.1
idf.py set-target esp32
for filename in production/*jade*.defaults configs/*jade*.defaults; do
    [[ $filename == *"v2"* ]] && continue
    rm -fr sdkconfig sdkconfig.defaults
    idf.py -D SDKCONFIG_DEFAULTS="${filename}" reconfigure save-defconfig
    tail -n +4 sdkconfig.defaults | LC_ALL=C sort -o ${filename}.tmp
    # add the first line from the original file back if it was a comment
    head -n 1 ${filename} | grep -q '^#' && echo "$(head -n 1 ${filename}; cat ${filename}.tmp)" > ${filename}.tmp
    mv ${filename}.tmp ${filename}
done
rm -fr sdkconfig sdkconfig.defaults build managed_components
