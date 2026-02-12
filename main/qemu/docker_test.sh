#!/usr/bin/env bash
set -e

pushd /opt/esp/idf && . ./export.sh && popd

# Build the qemu variant of the firmware
cd /jade
rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all

# Build the bsdiff tool in the 'tools' directory
gcc -O2 -DBSDIFF_EXECUTABLE -o tools/bsdiff components/esp32_bsdiff/bsdiff.c

# Compress the built firmware using the standard tools
./tools/fwprep.py build/jade.bin build

# Make the initial bootable flash image
./main/qemu/make-flash-img.sh

# Run the qemu ci tests
./main/qemu/qemu_ci_flash.sh
