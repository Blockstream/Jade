# libjade

libjade provides the Jade firmware in a native library.

It can be thought of as an emulated or virtual Jade device that runs using
native code in the address space of the application linked to it.

libjade exposes several RPC calls that allow an external program to read
and write storage, fetch the screen contents, and push input events and
camera images to/from the emulated device. These RPC calls mean that a libjade
instance is NOT SECURE FROM EXTERNAL APPLICATIONS, and that SECRET DATA CAN
BE READ FROM THE RUNNING FIRMWARE.

This initial implementation is HIGHLY EXPERIMENTAL AND INCOMPLETE, and
should UNDER NO CIRCUMSTANCES BE USED BEYOND DEVELOPMENT AND TESTING.

## Building and running

libjade is built using cmake. You must have `IDF_PATH` set in your environment
in the same way as when doing normal jade development. Note that the idf
tooling is not used, but the idf-provided mbed-tls library is built natively.

To build, run:

```
./libjade/make_libjade.sh [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize]
```

The above command builds the files `libjade.so`, `libjade_static.a` and
`libjade_daemon` in the directory `build_linux/libjade/`.

Use `--help` to print other command line options.

See `libjade/libjade.h` for the exposed programmatic interface, and
the function `process_libjade_request()` in `libjade/libjade.c` to
see the available libjade-specific RPC calls available.

The standard build above can be used with `test_jade.py` to run the jade
tests from the root directory of this repo:

```
LD_LIBRARY_PATH=./build_linux/libjade:$LD_LIBRARY_PATH python test_jade.py --libjade
```

Note that the standard build uses CI-mode, where the firmware auto-selects a
default option (OK/continue) instead of waiting for user input. To provide
your own user input programmatically, build with `--no-ci` (see `--help`).

### From Python

When the `libjade.so` shared library is available in LD_LIBRARY_PATH, the
JadeAPI.create_libjade() function can be used to run libjade in-process.

The separate daemon process `libjade_daemon` can be run to expose a serial,
socket or tcp connection that the existing JadeAPI can connect to.

### Desktop Testing

An example GUI application is available in `libjade/gui.py`, allowing
desktop interaction with a libjade instance for development and testing.
GUI, NVS storage and camera support are available, in addition to a
python console that allows the jade to be programmatically manipulated.

To build and run the example, use:

```
./libjade/run_libjade_gui.sh [--daemon] [Debug|Release|RelWithDebInfo|MinSizeRel|Sanitize]
```

Use `--help` to print other command line options.

## Status

- All message handlers are implemented. OTA is untested.
- GUI activities arising from the dashboard process are currently leaked.
- Some operations that are expected to be constant-time are currently not.
- Sensitive stack clearing is not implemented.
- Memory is not locked from paging.
- No safety or security analysis has been performed on any code under the
  `libjade/` directory.
- The programmatic interface is not stable and may change in future releases,
  including in incompatible ways.

## Implementation

Portions of the expected runtime/hardware environment are implemented using
native code stubs. Some portions of the firmware itself are also
re-implemented as stubs.

On startup, the firmware code runs in a separate thread and processes
messages using the standard CBOR interface and the standard firmware code.
Threads for the GUI, events etc are handled in the same way as the native
firmware, using the host O/S threading support via pthreads.
