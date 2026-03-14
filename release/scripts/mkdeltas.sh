#!/bin/bash

INDEX="DELTAS"
HWDIRS="jade jade1.1 jade2.0 jade2.0c jadedev jade1.1dev jade2.0dev jade2.0cdev"

PATTERN_BLE="_ble_*_fw.bin"
PATTERN_NORADIO="_noradio_*_fw.bin"
PATTERN_DELTA="*_from_*_sizes_*_patch.bin"
DELTA_OUTPUT_DIR="deltas"

STAGING="staging"
UPLOAD="upload"
WORKING_DIR="${STAGING}/${UPLOAD}"

if [ -z "${1}" ]
then
  echo "Usage ${0} <target-version> [ <prior version> [ <prior version> ... ]]"
  exit 1
fi
VER_DEST="${1}"
shift
VER_PRIORS="${*}"

# Relative paths from where it will be referenced in
# jade/release/staging/upload/<hw flavour>
MKPATCH="../../../../tools/mkpatch.py"

pushd "${WORKING_DIR}"
for hwdir in ${HWDIRS}
do
  pushd "${hwdir}"
  echo "Generating new deltas for $(pwd)"
  mkdir -p "${DELTA_OUTPUT_DIR}"

  if [ -n "${VER_PRIORS}" ]
  then
    # Upgrade & downgrade deltas
    for pattern in "${PATTERN_BLE}" "${PATTERN_NORADIO}"
    do
      fw_dest=$(ls ${VER_DEST}${pattern})
      if [ -r "${fw_dest}" ]
      then
        for ver_prior in ${VER_PRIORS}
        do
          fw_prior=$(ls ${ver_prior}${pattern})
          if [ -r "${fw_prior}" ]
          then
            "${MKPATCH}" "${fw_prior}" "${fw_dest}" "${DELTA_OUTPUT_DIR}"
          fi
        done
      fi
    done
  fi

  # BLE<->NORADIO deltas for target fw
  fw_ble=$(ls ${VER_DEST}${PATTERN_BLE})
  fw_noradio=$(ls ${VER_DEST}${PATTERN_NORADIO})

  if [ -r "${fw_ble}" -a -r "${fw_noradio}" ]
  then
    "${MKPATCH}" "${fw_noradio}" "${fw_ble}" "${DELTA_OUTPUT_DIR}"
  fi

  ls -r "${DELTA_OUTPUT_DIR}"/${PATTERN_DELTA} > "${INDEX}"
  popd
done
popd
