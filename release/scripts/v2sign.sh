#!/bin/bash

set -e

if [ -z "${1}" -o -z "${2}" ]
then
    echo "Usage: ${0} <version/dir> <key_label>"
    exit 1
fi
VER_DIR="${1}"
KEY_LABEL="${2}"

WORKING_DIR_PREFIX="staging/${VER_DIR}"
HWDIRS="jade2.0 jade2.0c"

# Relative paths from where it will be referenced in fw dir
KEY="../../../scripts/${KEY_LABEL}.pem"
PUBKEY="../../../scripts/${KEY_LABEL}.pub"

BLEDIR="build_v2_prod"
NORADIODIR="build_v2_noradio_prod"

FILE_PREFIX="v2_${VER_DIR}"
SIG_SUFFIX="${KEY_LABEL}.sig"

HASH_OPTS="-sha256 -binary"
SIGN_OPTS="-inkey ${KEY} -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32 -pkeyopt rsa_mgf1_md:sha256"
VERIFY_OPTS="-pubin -inkey ${PUBKEY} -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss"

for hwdir in ${HWDIRS}; do
    WORKING_DIR="${WORKING_DIR_PREFIX}/${hwdir}"

    pushd "${WORKING_DIR}"

    [ -f ${PUBKEY} ] || (echo "Public key file ${PUBKEY} not found" && exit 2)
    [ -f ${KEY} ] || (echo "Private key file ${KEY} not found" && exit 2)

    # Verify bootloaders are same
    sha1=$(sha256sum "${BLEDIR}/bootloader/bootloader.bin" | cut -d\  -f1)
    sha2=$(sha256sum "${NORADIODIR}/bootloader/bootloader.bin" | cut -d\  -f1)
    if [ -z "${sha1}" -o -z "${sha2}" -o "${sha1}" != "${sha2}" ]
    then
        echo "Bootloaders missing or differ!"
        popd
        exit 2
    fi

    # Copy binaries that need signing
    cp "${BLEDIR}/bootloader/bootloader.bin" "${FILE_PREFIX}_ble_bootloader.bin"
    cp "${BLEDIR}/jade.bin" "${FILE_PREFIX}_ble_jade.bin"
    cp "${NORADIODIR}/bootloader/bootloader.bin" "${FILE_PREFIX}_noradio_bootloader.bin"
    cp "${NORADIODIR}/jade.bin" "${FILE_PREFIX}_noradio_jade.bin"

    # Hash the bootloaders and fws locally
    for build in "ble" "noradio"
    do
        for program in "bootloader" "jade"
        do
            filename_root="${FILE_PREFIX}_${build}_${program}"
            binary="${filename_root}.bin"
            hash_file="${filename_root}.hash"
            sig_file="${filename_root}.${SIG_SUFFIX}"

            openssl dgst ${HASH_OPTS} -out "${hash_file}" "${binary}"
            openssl pkeyutl -sign ${SIGN_OPTS} -in "${hash_file}" -out "${sig_file}"
            openssl pkeyutl -verify ${VERIFY_OPTS} -sigfile "${sig_file}" -in "${hash_file}"
            if [ "${?}" -eq 0 ]
            then
                rm "${hash_file}"
            else
                echo "Signature verification of ${sig_file} over ${hash_file} with ${PUBKEY} failed"
            fi
        done
    done

    sha256sum *."${SIG_SUFFIX}"

    popd

done
