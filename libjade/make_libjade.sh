#!/bin/bash
#
# Build the Jade firmware into a shared library for in-process debugging
#
# ./libjade/make_libjade.sh [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize] [--log] [--camera] [--no-ci] [--coverage] [--display v1|v2]
#
set -e

BUILD_TYPE="Debug"
LOG="0"
CI="CI"
CAMERA="0"
JADE_DISPLAY="v2"

usage() {
    echo "Usage: $0 [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize] [--log] [--camera] [--no-ci] [--coverage] [--display v1|v2]"
    exit 1
}

# iterate through optional arguments and set variables accordingly
while [ $# -gt 0 ]; do
    case "$1" in
        --help)
            usage
            ;;
        Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize)
            BUILD_TYPE="$1"
            ;;
        --coverage)
            COVERAGE="COVERAGE"
            ;;
        --log)
            LOG="LOG"
            ;;
        --no-ci)
            CI="0"
            ;;
        --camera)
            CAMERA="CAMERA"
            ;;
        --display)
            shift
            case "$1" in
                v1|v2) JADE_DISPLAY="$1" ;;
                *) echo "Invalid display: $1"; usage ;;
            esac
            ;;
        *)
            break
            ;;
    esac
    shift
done

mkdir -p build_linux
cd build_linux
EXTRA_ARGS=''
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    EXTRA_ARGS='-DCMAKE_C_FLAGS"-fsanitize=undefined" -DCMAKE_CXX_FLAGS"-fsanitize=undefined"'
fi
cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${EXTRA_ARGS} -DLOG=${LOG} -DCOVERAGE=${COVERAGE} -DCAMERA=${CAMERA} -DCI=${CI} -DJADE_DISPLAY=${JADE_DISPLAY} $* ..
make -j8
cd ..

echo "to use libjade set LD_LIBRARY_PATH=$PWD/build_linux/libjade"
if [ "${BUILD_TYPE}" == "Sanitize" ]; then
    echo "and ASAN_OPTIONS=symbolize=1,detect_leaks=0 LD_PRELOAD=$(ls /usr/lib/gcc/x86_64-linux-gnu/*/libasan.so) UBSAN_OPTIONS=print_stacktrace=1"
fi
