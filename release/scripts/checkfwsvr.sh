#!/bin/bash

LOCAL_DIR="${1:-fwsvr_mirror}"
MISSING_LOG="missing.log"
EXTRA_LOG="extra.log"
GCLOUD_BUCKET="gs://jadefw.blockstream.com/bin"
HWDIRS="jade jade1.1 jade2.0 jadedev jade1.1dev jade2.0dev"

if [ $(basename $PWD) != "release" ]; then
    if [ $(basename $PWD) != "staging" ]; then
        echo "ERROR: This script must be run from the 'release' or 'staging' source directory"
        exit 1
    fi
fi

echo "Checking authentication:"
if ! echo "" | gcloud projects list &> /dev/null; then
    echo "ERROR: You must run 'gcloud login' to authenticate to gcloud"
    exit 1
fi

echo "Syncing firmware server files into ${LOCAL_DIR}"
# This always give an error, either:
# ERROR: [Errno 20] Not a directory: 'fwsvr_mirror/_.gstmp' -> 'fwsvr_mirror/'
# or:
# ERROR: [Errno 21] Is a directory: 'fwsvr_mirror/'
# but it doesn't affect the actual downloaded files
gcloud storage rsync ${GCLOUD_BUCKET} ${LOCAL_DIR} --recursive --delete-unmatched-destination-objects
# We always get this file too even though it doesn't appear to exist in the bucket.
rm -f ${LOCAL_DIR}/_.gstmp

echo "Checking firmware server files, hashes and indices"
rm -f "${MISSING_LOG}" "${EXTRA_LOG}"

function get_uncompressed_hash() {
    # We add a gzip header to allow gzip to decompress the zlib data
    printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" | cat - $1 | \
        gzip -qdc 2>/dev/null | sha256sum | cut -d ' ' -f 1
}

for hwdir in ${HWDIRS}; do
    for index_name in index.json LATEST BETA PREVIOUS; do
        index_file="${LOCAL_DIR}/${hwdir}/${index_name}"
        delta_file_names=""
        if [ ! -f "${index_file}" ]; then
            echo "Missing Index: ${index_file}" >> "${MISSING_LOG}"
            fw_file_names=""
        else
            if [ "${index_name}" == index.json ]; then
                # jq filter: <roots>/<release types>/<fw types>/<filename>
                fw_file_names=$(jq -r ".[] | .[] | .[] | .filename" "${index_file}")
                delta_file_names=$(echo ${fw_file_names} | tr ' ' '\n' | \
                    grep "^deltas/" | sed 's/^deltas\///g' | sort | uniq)
            else
                fw_file_names=$(cat "${index_file}")
            fi
        fi

        for fw_file_name in $(echo "${fw_file_names}" | tr '\n' ' '); do
            fw_file="${LOCAL_DIR}/${hwdir}/${fw_file_name}"
            if [ ! -f "${fw_file}" ]; then
                echo "Missing FW ${fw_file} named in ${index_file}" >> "${MISSING_LOG}"
            fi
            case $fw_file_name in
                0\.1\.*) ;; # Ignore early FW versions without hashes
                *_fw.bin)
                    if [ ! -f "${fw_file}.hash" ]; then
                        echo "Missing hash for ${fw_file}" >> "${MISSING_LOG}"
                    fi
                    fw_hash=$(get_uncompressed_hash "${fw_file}")
                    if [ "${fw_hash}" != $(cat "${fw_file}.hash") ]; then
                        echo "ERROR: Hash mismatch for ${fw_file}!"
                        exit 1
                    fi
                    ;;
            esac
        done

        if [ -n "${delta_file_names}" ]; then
            # Find delta files present in the bucket but not in the index
            delta_files=$(ls ${LOCAL_DIR}/${hwdir}/deltas | sort | uniq)
            diffs=$(diff <(printf "%s\n" "${delta_files}") \
                <(printf "%s\n" "${delta_file_names}") \
                | grep '^< ' | sed 's/^< /rm -f /g')
            if [ -n "${diffs}" ]; then
                echo "pushd ${LOCAL_DIR}/${hwdir}/deltas" >> "${EXTRA_LOG}"
                printf "%s\n" "${diffs}" >> "${EXTRA_LOG}"
                echo "popd" >> "${EXTRA_LOG}"
            fi
        fi
    done
done

# TODO: find firmware files that are present but not listed in index.jon

if [ -f "${MISSING_LOG}" ]; then
  echo "ERROR: Missing files:"
  cat "${MISSING_LOG}"
  exit 1
fi
if [ -f "${EXTRA_LOG}" ]; then
  echo "ERROR: Extra files. remove with:"
  cat "${EXTRA_LOG}"
  exit 1
fi
echo "ALL GOOD!"
exit 0
