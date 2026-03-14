#!/bin/bash

set -e

INDEX="BETA"
DEVDIRS="jadedev jade1.1dev jade2.0dev jade2.0cdev"
BUILDDIRS="./build_dev_jade*"
FW_PATTERN="*_fw.bin"
HASH_PATTERN="*_fw.bin.hash"

UNSIGNED_BINARY="./jade.bin"
SIGNED_BINARY="./jade_signed.bin"

STAGING="staging"
UPLOAD="upload"

if [ -z "${1}" ]
then
  echo "Usage ${0} <version>"
  exit 1
fi
WORKING_DIR="${STAGING}/${1}"

# Relative paths from where it will be referenced in
# jade/release/staging/<working dir>/<hw flavour>/<build flavour>
DEV_KEY_DIR="../../../../scripts"
DEV_KEY_PRIV_A="${DEV_KEY_DIR}/dev_fw_signing_key_A.pem"
DEV_KEY_PRIV_B="${DEV_KEY_DIR}/dev_fw_signing_key_B.pem"
DEV_KEY_PRIV_C="${DEV_KEY_DIR}/dev_fw_signing_key_C.pem"
DEV_KEY_PUB_A="${DEV_KEY_DIR}/dev_fw_pub_key_A.pub"
DEV_KEY_PUB_B="${DEV_KEY_DIR}/dev_fw_pub_key_B.pub"
DEV_KEY_PUB_C="${DEV_KEY_DIR}/dev_fw_pub_key_C.pub"
FWPREP="../../../../../tools/fwprep.py"

pushd "${WORKING_DIR}"
for devdir in ${DEVDIRS}
do
  pushd "${devdir}"
  for dir in ${BUILDDIRS}
  do
    pushd "${dir}"

    # Sign the binary
    espsecure.py sign_data --keyfile "${DEV_KEY_PRIV_A}" --version 2 --output "${SIGNED_BINARY}" "${UNSIGNED_BINARY}"

    if [ "${devdir}" == "jade2.0dev" ]
    then
        # Append a second signature and verify
        espsecure.py sign_data --keyfile "${DEV_KEY_PRIV_B}" --version 2 --append_signatures "${SIGNED_BINARY}"
        espsecure.py verify_signature --version 2 --keyfile "${DEV_KEY_PUB_B}" "${SIGNED_BINARY}"
    fi

    espsecure.py verify_signature --version 2 --keyfile "${DEV_KEY_PUB_A}" "${SIGNED_BINARY}"
    "${FWPREP}" "${SIGNED_BINARY}" ..
    popd
  done

  ls ${FW_PATTERN} > "${INDEX}"
  cp ${FW_PATTERN} ${HASH_PATTERN} "${INDEX}" "../../${UPLOAD}/${devdir}"
  popd
done
popd
