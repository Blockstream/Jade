#!/bin/bash

pkill -f qemu-system-xtensa

(cd /qemu && build/qemu-system-xtensa -s -S -nographic \
    -machine esp32 \
    -m 4M \
    -drive file=flash_image.bin,if=mtd,format=raw \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:2222-:2222 \
    -drive file=qemu_efuse.bin,if=none,format=raw,id=efuse \
    -global driver=nvram.esp32.efuse,property=drive,value=efuse \
    -serial pty &)

sleep 2

xtensa-esp32-elf-gdb /jade/build/jade.elf \
    -ex "target remote :1234" \
    -ex "monitor system_reset" \
    -ex "tb app_main" -ex "c" \
    -ex "b main.c:120"\
    -ex 'info b' -ex 'set print pretty on'

