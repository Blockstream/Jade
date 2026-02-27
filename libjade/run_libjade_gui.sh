#!/bin/bash

set -e

usage() {
    echo "Usage: $0 [--inprocess | --daemon] [--nvs-file PATH] [--log-level none|error|warn|info|debug|verbose] [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize]"
    echo "  --inprocess  Load libjade.so directly in the GUI process (default)"
    echo "  --daemon     Run libjade as a separate daemon process"
    echo "  --nvs-file   NVS flash storage file (default: nvs_flash.bin)"
    echo "  --log-level  Set log verbosity (default: info)"
    exit 1
}

MODE="inprocess"
BUILD_TYPE="Debug"
NVS_FILE="nvs_flash.bin"
LOG_LEVEL="info"
CBOR_SOCKET="/tmp/jade_cbor.sock"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help) usage ;;
        --inprocess) MODE="inprocess"; shift ;;
        --daemon)    MODE="daemon"; shift ;;
        --nvs-file)
            shift
            NVS_FILE="$1"
            shift ;;
        --log-level)
            shift
            case "$1" in
                none|error|warn|info|debug|verbose) LOG_LEVEL="$1" ;;
                *) echo "Invalid log level: $1"; usage ;;
            esac
            shift ;;
        Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize) BUILD_TYPE="$1"; shift ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
JADE_PATH=$(realpath $SCRIPT_DIR/..)
if [ ! -d "$JADE_PATH" ]; then
    echo "Error: Jade directory not found at $JADE_PATH"
    exit 1
fi

echo "--------------------------------"
echo "Building libjade ($MODE mode, $BUILD_TYPE)..."
echo "--------------------------------"
$JADE_PATH/libjade/make_libjade.sh $BUILD_TYPE --log --camera --no-ci

if [ "$BUILD_TYPE" == "Sanitize" ]; then
    export ASAN_OPTIONS=symbolize=1:detect_leaks=0
    export LD_PRELOAD=$(ls /usr/lib/gcc/x86_64-linux-gnu/*/libasan.so | tail -n1)
    export UBSAN_OPTIONS=print_stacktrace=1
fi

if [ "$MODE" == "daemon" ]; then
    DAEMON_BIN=$JADE_PATH/build_linux/libjade/libjade_daemon
    echo "--------------------------------"
    echo "Starting libjade daemon..."
    echo "  CBOR socket : $CBOR_SOCKET"
    echo "--------------------------------"

    "$DAEMON_BIN" --socketfile "$CBOR_SOCKET" --log-level "$LOG_LEVEL" &
    DAEMON_PID=$!

    cleanup() {
        echo "Stopping libjade daemon (pid $DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        rm -f "$CBOR_SOCKET"
    }
    trap cleanup EXIT INT TERM

    # wait for daemon to create its socket file (up to 10s)
    echo "Waiting for daemon sockets..."
    for i in $(seq 1 100); do
        if [ -S "$CBOR_SOCKET" ]; then
            echo "Daemon socket ready."
            break
        fi
        if [ "$i" -eq 100 ]; then
            echo "Error: daemon socket did not appear after 10s" >&2
            exit 1
        fi
        sleep 0.1
    done

    echo "--------------------------------"
    echo "Running Jade GUI (daemon mode)..."
    echo "--------------------------------"
    python $JADE_PATH/libjade/gui.py --device "tcp:$CBOR_SOCKET" --nvs-file "$NVS_FILE" --log-level "$LOG_LEVEL"
else
    export LD_LIBRARY_PATH=$JADE_PATH/build_linux/libjade:$LD_LIBRARY_PATH
    echo "--------------------------------"
    echo "Running Jade GUI (in-process mode)..."
    echo "--------------------------------"
    python $JADE_PATH/libjade/gui.py --nvs-file "$NVS_FILE" --log-level "$LOG_LEVEL"
fi
