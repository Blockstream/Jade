# Reproducible Build

The following assumes the jade repo is cloned, checked-out to the appropriate release tag, and all submodules updated.

> To initalize and update submodules, run the following:
> ```
> git submodule init
> git submodule update
> ```

NOTE: DO NOT TRY TO FLASH OR OTA THESE BUILD ARTIFACTS ONTO A JADE OR ANY OTHER ESP32 HARDWARE.

They contain settings to encrypt the flash and to enable 'secure boot' - this burns 'efuses' on the device - a one-way operation, and may render the device unusable.  
As the built firmware does not include the Blockstream signature, the fw will not run on an official Blockstream Jade device.

The purpose of these builds is purely to reproduce the build and hence verify the firmware offered by Blockstream is indeed built from the publicly available tagged source code.

1. Create Docker image

Use `Dockerfile` to create a docker image for building the Jade firmware - this builds/installs the required tools from their public repos on a Debian base - the resultant image should be the same as the one used to build the official firmware binaries.
(NOTE: Because the Dockerfile executes 'apt install' commands, the point versions of some tools may change, so the image may not be completely identical - but these differences should be minor and are not expected to affect the build result in most cases.)
```
DOCKER_BUILDKIT=1 docker build -f ./Dockerfile -t jade_builder .
```

2. Run the container
```
docker run -v ${PWD}:/builds/blockstream/jade --name jade_builder -it jade_builder bash
```
NOTE: The path where the jade repo is mapped (`/builds/blockstream/jade`) is encoded into the intermediate build files `jade.map` and `jade.elf`, and a hash of the ELF file is included in the final binary - so this path must be correct for the binaries to correctly reflect the Blockstream official build.

All following commands are to be run inside the 'jade_builder' docker container.

3. Prepare the build environment
```
. /root/esp/esp-idf/export.sh
cd /builds/blockstream/jade
git config --global --add safe.directory /builds/blockstream/jade
```
Since the mounted source repository will have a different owner from the user running the shell in the container, `git describe` (which is used internally in the build process to generate/include an application version tag) may fail.  The `git config` command above should address this and ensure the correct version tag is included in the firmware image being built.

* RE-RUN FROM HERE TO BUILD DIFFERENT CONFIGURATIONS

4. Generate the relevant config file

Generate the relevant config file to `./sdkconfig.defaults` using the script `tools/switch_to.sh`.

| Jade Hardware Type          | Configuration | Command                                   |
| --------------------------- | ------------- | ------------------------------------------|
| Jade 1.0 (true wheel)       | BLE-enabled   | ./tools/switch_to.sh jade                 |
|                             | no-radio      | ./tools/switch_to.sh jade --noradio       |
| Jade 1.1 (rocker/jog-wheel) | BLE-enabled   | ./tools/switch_to.sh jade_v1_1            |
|                             | no-radio      | ./tools/switch_to.sh jade_v1_1 --noradio  |
| Jade 2.0 (two buttons)      | BLE-enabled   | ./tools/switch_to.sh jade_v2              |
|                             | no-radio      | ./tools/switch_to.sh jade_v2 --noradio    |

5. Build
```
idf.py fullclean all
```
This makes a fw file `build/jade.bin`.

6. Sign the binary with the 'dev' key
```
espsecure.py sign_data --keyfile ./release/scripts/dev_fw_signing_key.pem --version 2 --output ./build/jade_signed.bin ./build/jade.bin
```

7. Compare signed and unsigned binaries

A diff of `./build/jade_signed.bin` against `./build/jade.bin` should just show extra padding and data suffixed to the binary - this is the signature block.
(A hex dump can be obtained using `xxd`, which is perhaps easier to diff)

# Download Blockstream Jade Firmware

1. Download the official Blockstream Jade firmware, by supplying the relevant `hw-target` flag:

| Jade Hardware Type                 | flag                 |
| ---------------------------------- | -------------------- |
| Jade 1.0 (true wheel)              | --hw-target jade     |
| Jade 1.1 (rocker/jog-wheel)        | --hw-target jade1.1  |
| Jade 2.0 (two buttons)             | --hw-target jade2.0  |
| Jade 2.0c (2.0, no camera/battery) | --hw-target jade2.0c |

eg:
```
pip install -r ./requirements.txt
python ./jade_ota.py --skipserial --skipble --write-compressed --download-firmware --release stable --hw-target jade
```
Select the full firmware image as appropriate (BLE-enabled or no-radio) - NOTE: ignore the 'deltas' at this time.
```
2)  0.1.33 - ble
```

This should write the compressed firmware image to the build/ directory, eg `./build/0.1.33_ble_1118208_fw.bin`   A `.hash` file may also be written.  If so, this contains the hex hash of the firmware image when uncompresed.

NOTE: Ensure no Jade is connected, and that `--skipserial --skipble` are definitely present on the command line - otherwise `jade_ota.py` may attempt to upload the firmware onto the connected Jade!

NOTE: this initial step can be skipped if the downloaded firmware is already present, eg. from a prior run of `jade_ota.py` or `update_jade_fw.py`.

2. Uncompress the downloaded firmware
```
apt update && apt install pigz
mv build/0.1.33_ble_1118208_fw.bin build/0.1.33_ble_1118208_fw.bin.gz && pigz -z -d build/0.1.33_ble_1118208_fw.bin.gz
```
This should write the uncompressed firmware to the build directory, eg: `./build/0.1.33_ble_1118208_fw.bin`

NOTE: the sha25sum hash of this uncompressed file should match the value in the associated .hash file, if present.

3. Compare

A diff of the uncompressed downloaded binary against the locally built `./build/jade.bin` should just show extra padding and data suffixed to the binary - this is the Blockstream signature block.

A diff of the uncompressed downloaded binary against `./build/jade_signed.bin` should just show differences in that trailing the signature block.
(A hex dump can be obtained using `xxd`, which is perhaps easier to diff)

# Delta Firmwares

Since `0.1.33` it has been possible to update Jade firmware using binary deltas.  In this case a 'diff' between the currently running firmware and the desired target firmware is uploaded and applied.  These deltas are much smaller than a complete firmware image.  Verifying these patches is straightforward assuming the relevant full firmware images have been verified as above, as the patch is simply a binary diff between two signed firmware images.

1. Obtain signed/downloaded full firmware images

Take two signed firmware images provided by Blockstream, eg. `0.1.33_ble_1118208_fw.bin` and `0.1.34_ble_1118208_fw.bin`
NOTE: it may be necessary to pass `--release previous` when downloading the firmware, in order to access older versions.

2. If necessary, verify these images

Verify these firmware images match the tagged source code using the steps described above.

3. Create patches

Create the compressed binary diff patches between the two signed/downloaded firmware images
```
mkdir patches
./tools/mkpatch.py 0.1.33_ble_1118208_fw.bin 0.1.34_ble_1118208_fw.bin patches
```
This should create two patches for converting between these firmware images, one for each 'direction'.

NOTE: it may be necessary to compile the `bsdiff` tool:
```
gcc -O2 -DBSDIFF_EXECUTABLE -o tools/bsdiff components/esp32_bsdiff/bsdiff.c
```

4. Download the Blockstream provided patch
```
python ./jade_ota.py --skipserial --skipble --write-compressed --download-firmware --release stable --hw-target jade
```
Select the relevant delta/patch - eg:
```
6)  0.1.34 - ble      FROM  0.1.33 - ble
```

5. Compare

The dowloaded patch file and the patch created locally ought to be identical.
This can be verified with `diff`, or better still with `sha256sum` - the hashes of the files should be identical.
