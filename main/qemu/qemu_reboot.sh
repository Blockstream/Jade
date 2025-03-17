#!/bin/bash

set -eo pipefail

. $HOME/esp/esp-idf/export.sh

pkill -f qemu-system-xtensa || true

qemu-system-xtensa -nographic \
    -machine esp32 \
    -m 4M \
    -drive file=/flash_image.bin,if=mtd,format=raw \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:30121-:30121 \
    -drive file=/qemu_efuse.bin,if=none,format=raw,id=efuse \
    -global driver=nvram.esp32.efuse,property=drive,value=efuse \
    -serial pty &
