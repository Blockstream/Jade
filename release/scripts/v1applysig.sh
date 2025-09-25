#!/bin/bash

set -e

if [ -z "${1}" -o -z "${2}" ]
then
    echo "Usage: ${0} <version/dir> <key_file>"
    exit 1
fi
VER_DIR="${1}"
KEY=$(realpath ${2})

[ -d staging/${VER_DIR} ] || false # Version directory must exist
[ -f ${KEY} ] || false # Private key file must exist

VARIANTS="jade jade1.1"

for variant in  ${VARIANTS}; do
    for build_dir in staging/${VER_DIR}/${variant}/build_*prod; do
        pushd ${build_dir}
        espsecure.py sign_data --version 2 --keyfile ${KEY} --output bootloader/bootloader_signed.bin bootloader/bootloader.bin
        espsecure.py sign_data --version 2 --keyfile ${KEY} --output jade_signed.bin jade.bin
        popd
    done
done
