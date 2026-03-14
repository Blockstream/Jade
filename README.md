# Jade Firmware Development

* DO NOT ATTEMPT TO BUILD/FLASH WITH OFFICIAL BLOCKSTREAM JADE HARDWARE UNITS

The below instructions are for developers with access to Jade development
devices, or for those wanting to build and flash their own esp32/esp32s3
DIY consumer devices such as M5Stack or TTGO T-Display boards.

Official Blockstream Jade hardware units can only be updated via a supported
companion app, or by using the [Firmware Update Instructions](./FWUPDATE.md).

# DIY Hardware & Programming Notes
For information about suitable DIY hardware, as well as suggested configuration
profiles and notes on secure boot, see the [DIY Guide](./diy/)

# Build dependencies

Cmake and ninja are needed to build Jade firmware images.

On Debian based distributions, install with with:

```
sudo apt install cmake ninja-build
```

On MacOS:

```
brew install cmake ninja
```

Make sure to use a recent Python version (Python 3.11+) when running the
commands below. Failure to do so may result in problems installing Python
dependencies.

# Set up the build environment

Jade requires the esp-idf SDK. You can use our docker image to build or
install the esp-idf toolchain locally using the commands below.

See the [Espressif official guide](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32/get-started/index.html)
for more information on the available tooling.

# Device targets

There are currently four official Jade device targets:
- jade: The original Jade 1.0 with a selection wheel.
- jade_v1_1: Jade 1.1, with a rocker/jog-wheel instead of the selection wheel.
- jade_v2: Jade Plus, with a larger screen and left/right selection buttons
  instead of a wheel or rocker.
- jade_v2c: Jade Core, Jade Plus without camera and battery.

Change `jade` in any calls to the `switch_to.sh` script below to the
appropriate device you wish to target from the list above.

# Serial port

The serial port pseudo-tty file for Jade access via USB is usually
`/dev/ttyACM0` or `/dev/ttyUSB0` (or `/dev/cu.SLAB_USBtoUART` on MacOS).

In order to have permission to use USB to install firmware, your user should
be in the `dialout` group on Debian based distributions. Other distributions
may use a different group name: Check the group of the serial port pseudo-tty
file using `ls -l` to determine the required group, e.g:

```
$ ls -l /dev/ttyACM0
crw-rw----+ 1 root dialout 166, 0 Apr 15 14:37 /dev/ttyACM0
```

The group name (`dialout` here) is shown after the owner (`root`). You can check
that `dialout` appears in your user groups by running:

```
$ groups
docker libvirt dialout storage kvm wheel plugdev
```

If not present you should add your user to the group:

```
sudo usermod -aG dialout $USER
```

You should then login/logout or reboot for the group changes to take effect.

**NOTE**: For docker builds no group changes are usually required as the
docker image is privileged.

You should set the environment variable `JADESERIALPORT` to the Jade USB
device to default its value when running development scripts.

## Docker build environment

NOTE: MacOS users should set up the environment locally as detailed below to
avoid issues with device access. For more information see
[this article](https://dev.to/rubberduck/using-usb-with-docker-for-mac-3fdd).

Blockstream provides the `blockstream/jade_build` docker image which provides
the idf tooling and other dependencies required to build. To run a shell inside
the Jade development builder, use:

```
docker run -it blockstream/jade_build:latest bash
```

Run `get_idf` within this container to enable the idf tools.

Alternately, the `docker-compose.yml` file in this repository can be used to
work on the current respository source code from within the `jade_build`
container.

```
$ # Build the image and run a shell inside it
$ docker compose run dev bash
(docker)$ Set up idf environment
(docker)$ get_idf
(docker)# Make the serial device available to internal scripts, for example:
(docker)$ export JADESERIALPORT=/dev/ttyACM0
```

You can then build and flash as detailed below.

## Local build environment

Install the esp-idf SDK and required tools. From a checked-out Jade
git repository, run the following commands:

```
$ export ESP_IDF_BRANCH=$(grep ESP_IDF_BRANCH Dockerfile | sed 's/.*=//g')
$ mkdir ~/esp
$ cd ~/esp
$ git clone --recursive https://github.com/espressif/esp-idf.git
$ cd esp-idf
$ git checkout $ESP_IDF_BRANCH
$ ./install.sh --enable-gdbgui esp32 esp32s3
$ python ./tools/idf_tools.py install qemu-xtensa
```

Set up the idf environment to make the `idf.py` command available,
and then install the Jade dependencies into the idf environment:

```
$ . ~/esp/esp-idf/export.sh
$ pip install --require-hashes -r ./requirements.txt
```

You can then build and flash as detailed below.

# Build The firmware

First, you'll need the Jade source code including its sub-modules checked out:

```
git clone --recursive https://github.com/Blockstream/Jade.git $HOME/jade
cd $HOME/jade
git submodule update --init --recursive
```

Choose your configuration. For official Jade devices, the script `tools/switch_to.sh` allows
choosing the device and features you want. Run `tools/switch_to.sh --help` to see the
available options. A standard development Jade Plus build for example would use something
like:

```
$ ./tools/switch_to.sh jade_v2 --dev --log --jtag [--noradio]
```

For other devices, copy (and modify if desired) a suitable config from the `configs`
directory to `sdkconfig.defaults`. You should also run e.g. `idf.py set-target esp32` or
`idf.py set-target esp32s3` once initially to ensure you are targeting the correct
toolchain for your hardware. So for example for the TTGO T-Display:

```
$ cp configs/sdkconfig_display_ttgo_tdisplay.defaults sdkconfig.defaults
```

To build the firmware, run:

```
$ idf.py all
```

To flash the resulting build to your device, run:

```
$ idf.py -p $JADESERIALPORT flash [monitor]
```

Some hardware configurations (e.g. M5StickC-Plus) may not support the default baud
rate and so won't be detected. If this occurs you can force a specific baud rate
for flash/monitor by using the `-b` argument, e.g:

```
idf.py -p $JADESERIALPORT -b 115200 flash [monitor]
```

If you have errors relating to unknown bytes when flashing, place your device
into download mode. This is device specific, for Jade development devices,
turn off the device, then hold the select and power buttons for 10 seconds.
Note the device screen will stay blank when in download mode.

If you switch between JTAG and non-JTAG builds in particular, you will need to
flash from download mode.

If you flash multiple device types, or make changes to the sdkconfig.config file,
delete the `sdkconfig` file that gets created from `sdkconfig.defaults` between
builds. Otherwise, your changes will not get picked up when re-building/flashing
the firmware.

# Build customization

Beyond the build configurations in the `configs/` directory, you can edit the config
manually with the `menuconfig` tool:

```
$ idf.py menuconfig
```

**NOTE**: for any but the simplest CI-like build with no GUI, no camera, no
user-interaction etc. it is recommended that PSRAM (available under
`Component Config -> ESP-32 specific -> Support external SPI connected RAM`
is available and enabled.

# Run the tests

Virtualenv and bluez-tools are required, you can install them on Debian
based distributions with:

```
sudo apt install virtualenv bluez-tools
```

Then to run the tests:

```
$ cd $HOME/jade
$ # Create and activate a Python virtualenv
$ virtualenv -p python3 venv3
$ source venv3/bin/activate
$ pip install -r requirements.txt
$ pip install -r pinserver/requirements.txt
$ # Run the tests
$ python test_jade.py --serialport $JADESERIALPORT
$ # Cleanup
$ deactivate
```

The tests require a CI build; this is a configuration that automatically
accepts the default action without requiring user interaction. This is enabled using
the `--ci` argument to `switch_to.sh` or by setting `CONFIG_DEBUG_UNATTENDED_CI=y`
in sdkconfig.defaults.

Debug support is also required to expose debug functions for testing. Use `--debug`
or set `CONFIG_DEBUG_MODE=y` to enable this.

# Emulator/Virtualizer (qemu in Docker)

The firmware can be built and run under emulation via qemu:

```
$ # Build the default Jade emulation image (debug CI build)
$ docker build -t jade-qemu -f Dockerfile.qemu .
$
$ # Pass switch_to.sh args via QEMU_CONFIG_ARGS, e.g. for a no-psram build:
$ docker build -t jade-qemu -f Dockerfile.qemu . --build-arg QEMU_CONFIG_ARGS="--dev --ci"
$
$ # Pass `--build-arg QEMU_GDB="--gdb"` to enable gdb debugging.
$
$ # For a web-enabled 'virtual Jade':
$ docker build -t jade-qemu -f Dockerfile.qemu . --build-arg QEMU_CONFIG_ARGS="--dev --psram --webdisplay"
$
$ # Point your browser to http://localhost:30122 to interface with the virtual Jade.
$ # Replace --webdisplay with --webdisplay-larger for a larger display.
```

Run any of the above images with e.g.:

```
$ # Note you can remove `-p 30122:30122` if not using --webdisplay
$ docker run --rm -p 30121:30121 -p 30122:30122 -it jade-qemu
```

The jadepy python package can talk to the emulated jade via serial over tcp.
Pass the device string `"tcp:localhost:30121"` when connecting, e.g.:

```
python -c "from jadepy.jade import JadeAPI; jade = JadeAPI.create_serial(device='tcp:localhost:30121'); jade.connect(); print(jade.get_version_info()); jade.disconnect()"
```

# Reproducible Build

See [REPRODUCIBLE.md](./REPRODUCIBLE.md) for instructions on locally reproducing the official Blockstream Jade firmware images (minus the Blockstream signature block).

# DIY

Seen working on M5 Stack gray/black/FIRE, M5 Stick Plus, Core 2, Core S3, LilyGO T-Display, T-DisplayS3, RPI Zero + display shield (via QEMU), and Desktop via Qemu (browser for display/webcam).

# Client

A python client is available to communicate with genuine or DIY Jade units:

```
pip install jade-client
```

This installs the `jadepy` directory from this repository.  See [jade-client-requirements.txt](./jade-client-requirements.txt) and [jade-client-requirements.txt.asc](./jade-client-requirements.txt.asc)

# Firmware development

See [libjade](./libjade/README.md) For a local build setup that allows for initial feature development and debugging off-device.

# License

The collection is subject to GPL3 but individual source components can be used under their specific licenses.
