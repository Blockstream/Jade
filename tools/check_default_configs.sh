#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    . ${HOME}/esp/esp-idf/export.sh
fi


for filename in production/*.defaults configs/*.defaults; do
    rm -fr sdkconfig sdkconfig.defaults
    idf.py -D SDKCONFIG_DEFAULTS="${filename}" reconfigure save-defconfig
    tail -n +4 sdkconfig.defaults > ${filename}
done
rm -fr sdkconfig sdkconfig.defaults build
