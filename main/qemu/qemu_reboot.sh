#!/bin/bash

pkill -f qemu-system-xtensa

(cd /qemu && build/qemu-system-xtensa -nographic \
    -machine esp32 \
    -drive file=flash_image.bin,if=mtd,format=raw \
    -global driver=timer.esp32.timg,property=wdt_disable,value=true \
    -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:2222-:2222 \
    -serial pty &)

