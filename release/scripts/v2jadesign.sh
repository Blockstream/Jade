#!/bin/bash

set -e

function usage {
    echo "Usage: ${0} <version/dir> <key_label> [--serialport PORT]"
}

VER_DIR=""
KEY_LABEL=""
JADE_SERIAL_ARG=""

while true; do
    case "$1" in
        --serialport) JADE_SERIAL_ARG="${1} ${2}"; shift 2 ;;
        -h | --help)
            usage;
            exit 0 ;;
        "") break ;;
        *)
            if [ -z "${VER_DIR}" ]; then
                VER_DIR="${1}"; shift;
            elif [ -z "${KEY_LABEL}" ]; then
                KEY_LABEL="${1}"; shift;
            else
                usage;
                exit 1
            fi ;;
    esac
done

if [ -z "${VER_DIR}" -o -z "${KEY_LABEL}" ]; then
    usage
    exit 1
fi

WORKING_DIR_PREFIX="staging/${VER_DIR}"
HWDIRS="jade2.0 jade2.0c"

# Can log if required
LOGGING=""
#LOGGING="--log INFO"

# Can fetch and check the pubkey from Jade - but slower and really no need
# as we verify the signature with the expected pubkey at the end.
CHECK_JADE_PUBKEY=""
JADE_PUBKEY_FILE="jade_signing_key.pub"
#CHECK_JADE_PUBKEY="--savepubkey ${JADE_PUBKEY_FILE}"

# Standard for Jade fw signing
KEYLEN=3072
INDEX=1784767589

# Relative paths from where it will be referenced in fw dir
PUBKEY="../../../scripts/${KEY_LABEL}.pub"

BLEDIR="build_v2_prod"
NORADIODIR="build_v2_noradio_prod"

FILE_PREFIX="v2_${VER_DIR}"
SIG_SUFFIX="${KEY_LABEL}.sig"

HASH_OPTS="-sha256 -binary"
VERIFY_OPTS="-pubin -inkey ${PUBKEY} -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss"
JADE_SIGN_CMD="python ../../../../jade_bip85_rsa_sign.py ${JADE_SERIAL_ARG} ${LOGGING} ${CHECK_JADE_PUBKEY} --keylen ${KEYLEN} --index ${INDEX} --digest-files"

for hwdir in ${HWDIRS}; do
    WORKING_DIR="${WORKING_DIR_PREFIX}/${hwdir}"

    pushd "${WORKING_DIR}"

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
    HASH_FILES=""
    for build in "ble" "noradio"
    do
        for program in "bootloader" "jade"
        do
            binary="${FILE_PREFIX}_${build}_${program}.bin"
            hash_file="${FILE_PREFIX}_${build}_${program}.hash"
            HASH_FILES="${HASH_FILES} ${hash_file}"

            openssl dgst ${HASH_OPTS} -out "${hash_file}" "${binary}"
        done
    done

    # Sign the hashes with jade
    echo "Please approve signing on your Jade device"
    ${JADE_SIGN_CMD} ${HASH_FILES}

    # Check signatures with labeled pubkey, and rename if good
    for build in "ble" "noradio"
    do
        for program in "bootloader" "jade"
        do
            hash_file="${FILE_PREFIX}_${build}_${program}.hash"
            sig_file="${hash_file}.sig"
            openssl pkeyutl -verify ${VERIFY_OPTS} -sigfile "${sig_file}" -in "${hash_file}"
            if [ "${?}" -eq 0 ]
            then
                mv ${sig_file} "${FILE_PREFIX}_${build}_${program}.${SIG_SUFFIX}"
                rm "${hash_file}"
            else
                echo "Signature verification of ${sig_file} over ${hash_file} with ${PUBKEY} failed"
            fi
        done
    done

    sha256sum *."${SIG_SUFFIX}"

    # Verify jade pubkey matches expected (if feched)
    if [ -n "${CHECK_JADE_PUBKEY}" ]
    then
        sha1=$(sha256sum "${PUBKEY}" | cut -d\  -f1)
        sha2=$(sha256sum "${JADE_PUBKEY_FILE}" | cut -d\  -f1)
        if [ -z "${sha1}" -o -z "${sha2}" -o "${sha1}" != "${sha2}" ]
        then
            echo "Error: Pubkey pem mismatch!"
        fi
    fi

    popd

done
