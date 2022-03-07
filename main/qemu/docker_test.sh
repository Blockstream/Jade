#!/usr/bin/env bash
set -e

. /root/esp/esp-idf/export.sh

# Build the qemu variant of the firmware
cd /jade
rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all

# Setup the python environment
virtualenv -p python3 /venv3
source /venv3/bin/activate
pip install -r requirements.txt

# Build the bsdiff tool in the 'tools' directory
gcc -O2 -DBSDIFF_EXECUTABLE -o tools/bsdiff components/esp32_bsdiff/bsdiff.c

# Compress the built firmware using the standard tools
./tools/fwprep.py build/jade.bin build

# Make the initial bootable flash image
./main/qemu/make-flash-img.sh

# Run the qemu ci tests
./main/qemu/qemu_ci_flash.sh
