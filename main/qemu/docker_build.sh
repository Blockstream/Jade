#!/usr/bin/env bash
set -e

# This script builds jade for the headless qemu emulator,
# and then builds the qemu boot image from that.
# Copies the 'qemu_run.sh' script to /qemu also, so the source
# '/jade' directories are not longer referenced.

# Build jade
. /root/esp/esp-idf/export.sh

cd /jade
rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all

# Make the qemu flash image
# This script creates the image in /qemu
./main/qemu/make-flash-img.sh

# Copy the qemu_run script there also
cp ./main/qemu/qemu_run.sh /qemu

