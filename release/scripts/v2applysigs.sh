#!/bin/bash

if [ -z "${1}" -o -z "${2}" ]
then
    echo "Usage: ${0} <version/dir> <key_label> [ <key_label> ... ]"
    exit 1
fi
VER_DIR="${1}"
shift
SIGNER_KEY_LABELS="$@"

WORKING_DIR="staging/${VER_DIR}/jade2.0"

BLEDIR="build_v2_prod"
NORADIODIR="build_v2_noradio_prod"

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
        espsecure.py signature_info_v2 "${outfile}"

        for pubkey in ${PUBKEYS}
        do
            espsecure.py verify_signature --version 2 --keyfile "${pubkey}" "${outfile}"
        done
    done

    sha256sum "${FILE_PREFIX}"_*_"${SIGNED_SUFFIX}"
done

# Copy main fw binaries that have been signed
cp "${FILE_PREFIX}_ble_jade_${SIGNED_SUFFIX}" "${BLEDIR}/jade_${SIGNED_SUFFIX}"
cp "${FILE_PREFIX}_noradio_jade_${SIGNED_SUFFIX}" "${NORADIODIR}/jade_${SIGNED_SUFFIX}"

popd
