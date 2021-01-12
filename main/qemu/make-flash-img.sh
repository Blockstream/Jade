#!/usr/bin/env bash
set -e

FLASH_IMAGE_FILE=/qemu/flash_image.bin
# this is how you create the initial file, however we don't do it at each run
# because something gets stuck during init which only gets fixed during a reboot
# and it seems related to the keychain. By reusing the checked in image the
# keychain is pre-initialized
# FIXME: fix/investigate keychain nvs init
# dd if=/dev/zero bs=1024 count=4096 of=${FLASH_IMAGE_FILE}

# using a precreated image
cp main/qemu/qemu_flash_image.bin ${FLASH_IMAGE_FILE}
dd if=build/bootloader/bootloader.bin bs=1 seek=$((0x1000)) of=${FLASH_IMAGE_FILE} conv=notrunc
dd if=build/partition_table/partition-table.bin bs=1 seek=$((0x9000)) of=${FLASH_IMAGE_FILE} conv=notrunc
dd if=build/ota_data_initial.bin bs=1 seek=$((0xe000)) of=${FLASH_IMAGE_FILE} conv=notrunc
dd if=build/jade.bin bs=1 seek=$((0x10000)) of=${FLASH_IMAGE_FILE} conv=notrunc
