#!/bin/bash

HWDIRS="jade jade1.1 jade2.0 jade2.0c jadedev jade1.1dev jade2.0dev jade2.0cdev"

STAGING="staging"
UPLOAD="upload"
WORKING_DIR="${STAGING}/${UPLOAD}"
FULL_FW_PATTERN="*_fw.bin"
TMP_DIR="tmp_hash"

if [ -z "${1}" ]
then
  echo "Usage ${0} <version> [ <version> ... ]"
  exit 1
fi

VERSIONS="${*}"

# Relative paths from where it will be referenced in
# jade/release/staging/upload/<hw flavour>
FWPREP="../../../../tools/fwprep.py"

pushd "${WORKING_DIR}"
for hwdir in ${HWDIRS}
do
  echo "Generating hash files for ${hwdir}"
  pushd ${hwdir}
  mkdir ${TMP_DIR}

  for ver in ${VERSIONS}
  do
    VER_HASH_PATTERN="${ver}_${FULL_FW_PATTERN}"
    echo "${VER_HASH_PATTERN}"

    for fwfile in ${VER_HASH_PATTERN}
    do
      echo "Generating hash file for ${fwfile}"
      tmpfile="${TMP_DIR}/${fwfile}.zz"
      cp "${fwfile}" "${tmpfile}"
      pigz -z -d "${tmpfile}"

      tmpfile="${TMP_DIR}/${fwfile}"
      "${FWPREP}" "${tmpfile}" "${TMP_DIR}"

      sha_orig=$(sha256sum ${fwfile} | cut -d\  -f1)
      sha_new=$(sha256sum ${tmpfile} | cut -d\  -f1)
      if [ "${sha_new}" == "${sha_orig}" ]
      then
          hashfile="${tmpfile}.hash"
          cp "${hashfile}" ./
      else
          echo "Error - sha256 mismatch for ${fwfile}"
      fi
    done
  done
  rm -fr ${TMP_DIR}
  popd
done

popd

