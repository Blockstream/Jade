# libjade

libjade provides the Jade firmware in a native library.

It can be thought of as an emulated or virtual Jade device that runs using
native code in the address space of the application linked to it.

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

See `libjade/libjade.h` for the exposed programmatic interface.

### Python

When the `libjade.so` shared library is available in LD_LIBRARY_PATH, the
JadeAPI.create_libjade() function can be used to run libjade in-process.

The separate daemon process `libjade_daemon` can be run to expose a serial,
socket or tcp connection that the existing JadeAPI can connect to.

## Status

- All message handlers are implemented. OTA is untested.
- The library currently always runs in CI mode (automatically chooses the
  default option for a given activity). In the future the ability to provide
  input to the firmware may be added.
- No GUI is currently exposed.
- GUI activities are currently leaked.
- No screen or emulation is available.
- Some operations that are expected to be constant-time are currently not.
- Sensitive stack clearing is not implemented.
- Memory is not locked from paging.
- No safety or security analysis has been performed on any code under the
  `libjade/` directory.
- The programmatic interface is not stable and may change at any time,
  including in incompatible ways.

## Implementation

Portions of the expected runtime environment are implemented using native
code stubs. Some portions of the firmware itself (e.g. the gui) are also
reimplemented as stubs.

On startup, the firmware code runs in a separate thread and processes
messages using the standard CBOR interface and the standard firmware code.
