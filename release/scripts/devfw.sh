#!/bin/bash

INDEX="BETA"
DEVDIRS="jadedev jade1.1dev jade2.0dev"
BUILDDIRS="./build_jade*_ndebug"
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
DEV_KEY_PRIV="${DEV_KEY_DIR}/dev_fw_signing_key.pem"
DEV_KEY_PUB="${DEV_KEY_DIR}/dev_fw_pub_key.pub"
FWPREP="../../../../../tools/fwprep.py"

pushd "${WORKING_DIR}"
for devdir in ${DEVDIRS}
do
  pushd "${devdir}"
  for dir in ${BUILDDIRS}
  do
    pushd "${dir}"
    espsecure.py sign_data --keyfile "${DEV_KEY_PRIV}" --version 2 --output "${SIGNED_BINARY}" "${UNSIGNED_BINARY}"
    espsecure.py verify_signature --version 2 --keyfile "${DEV_KEY_PUB}" "${SIGNED_BINARY}"
    "${FWPREP}" "${SIGNED_BINARY}" ..
    popd
  done

  ls ${FW_PATTERN} > "${INDEX}"
  cp ${FW_PATTERN} ${HASH_PATTERN} "${INDEX}" "../../${UPLOAD}/${devdir}"
  popd
done
popd
