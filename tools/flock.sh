#!/bin/bash

#
# use flock to ensure processes run sequentially
#

set -e

# lock name from first argument
LOCK_NAME=${1}
# normalize lock name to be filesystem friendly
LOCK_NAME=${LOCK_NAME//[^a-zA-Z0-9]/_}
# lock file path from normalized lock name
LOCK_FILE="/tmp/flock_${LOCK_NAME}.lock"

# process to run under lock from command line arguments
PROCESS_CMD=${@:2}

# acquire an exclusive lock with a timeout of 1 hour
if flock -x -w 3600 -E 200 "$LOCK_FILE" -c "$PROCESS_CMD"; then
    echo "script executed successfully."
else
    # check if the error was due to timeout (exit code 200)
    if [ $? -eq 200 ]; then
        echo "could not acquire lock within timeout period."
    else
        echo "script failed with an error."
    fi
    exit 1
fi
