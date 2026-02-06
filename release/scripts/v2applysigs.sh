#!/bin/bash
set -e

if [ -z "${1}" -o -z "${2}" ]
then
    echo "Usage: ${0} <version/dir> <key_label> [ <key_label> ... ]"
    exit 1
fi
VER_DIR="${1}"
shift
SIGNER_KEY_LABELS="$@"

WORKING_DIR_PREFIX="staging/${VER_DIR}"
HWDIRS="jade2.0 jade2.0c"

FILE_PREFIX="v2_${VER_DIR}"
FW_SUFFIX="bin"
SIGNED_SUFFIX="signed.bin"

BUILDS="ble noradio"
BINARIES="bootloader jade"

# Relative paths from where it will be referenced in fw dir
PUBKEYS=""
for key_label in ${SIGNER_KEY_LABELS}
do
    PUBKEYS="${PUBKEYS} ../../../scripts/${key_label}.pub"
done

for hwdir in ${HWDIRS}; do
    WORKING_DIR="${WORKING_DIR_PREFIX}/${hwdir}"
    if [ "$hwdir" == "jade2.0" ]; then
        BLEDIR="build_v2_prod"
        NORADIODIR="build_v2_noradio_prod"
    else
        BLEDIR="build_v2c_prod"
        NORADIODIR="build_v2c_noradio_prod"
    fi

    pushd "${WORKING_DIR}"

    for build in ${BUILDS}
    do
        for binary in ${BINARIES}
        do
            sig_files=""
            for key_label in ${SIGNER_KEY_LABELS}
            do
                sig_file="${FILE_PREFIX}_${build}_${binary}.${key_label}.sig"
                sig_files="${sig_files} ${sig_file}"
            done

            file_prefix="${FILE_PREFIX}_${build}_${binary}"
            infile="${file_prefix}.${FW_SUFFIX}"
            outfile="${file_prefix}_${SIGNED_SUFFIX}"

            espsecure.py sign_data --version 2 --pub-key ${PUBKEYS} --signature ${sig_files} --output "${outfile}" "${infile}"
            digests=""
            for pubkey in ${PUBKEYS}
            do
                # Verify the signature
                espsecure.py verify_signature --version 2 --keyfile "${pubkey}" "${outfile}"
                # Capture the signature digest
                digest=$(espsecure.py digest_sbv2_public_key --keyfile "${pubkey}" -o digest.bin >/dev/null && cat digest.bin | od -A n -t x1 | tr -d ' \n' && rm -f digest.bin)
                digests="$digests $digest"
        done
        # Make sure the signature digests match
        digests=$(echo ${digests} | tr ' ' '\n' | sort)
        file_digests=$(espsecure.py signature_info_v2 "${outfile}" | grep "Public key digest for block " | cut -d\: -f2 | sed "s/ //g" | sort)
        if [ "${digests}" != "${file_digests}" ]; then
            echo "mismatched digests:"
            echo "digests:"
            echo ${digests}
            echo "expected:"
            echo ${file_digests}
            exit 2
        fi
        done

    done
    sha256sum "${FILE_PREFIX}"_*_"${SIGNED_SUFFIX}"

    # Copy main fw binaries that have been signed, consistent with v1
    cp "${FILE_PREFIX}_ble_jade_${SIGNED_SUFFIX}" "${BLEDIR}/jade_${SIGNED_SUFFIX}"
    cp "${FILE_PREFIX}_noradio_jade_${SIGNED_SUFFIX}" "${NORADIODIR}/jade_${SIGNED_SUFFIX}"
    cp "${FILE_PREFIX}_ble_bootloader_${SIGNED_SUFFIX}" "${BLEDIR}/bootloader/bootloader_${SIGNED_SUFFIX}"
    cp "${FILE_PREFIX}_noradio_bootloader_${SIGNED_SUFFIX}" "${NORADIODIR}/bootloader/bootloader_${SIGNED_SUFFIX}"

    popd

done
