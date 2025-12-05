# Jade Firmware

NOTE: The below instructions are for Jade developers with access to Jade development boards or for those wanting to build and flash their own esp32/esp32s3 consumer devices - e.g. M5Stack or TTGO T-Display boards.
They are not for updating the firmware of an official Blockstream Jade HW unit - these can only be updated in-app, or using the 'update_jade_fw.py' script - see FWUPDATE.md

* DO NOT ATTEMPT THE BELOW WITH BLOCKSTREAM OFFICIAL BLOCKSTREAM JADE HW UNITS

To build you can use the docker image (see Dockerfile) or install the esp-idf toolchain and repository following the commands below.

# DIY Hardware & Programming Notes
For information about suitable DIY hardware, as well as suggested configuration profiles and notes on secure boot,
see [DIY Guide](./diy/)

# Build dependencies

Cmake and ninja are needed to build the firmware.

On Debian based distributions, install with with:

```
sudo apt install cmake ninja-build
```

On MacOS:

```
brew install cmake ninja
```

Make sure to use a recent Python version (e.g. Python 3.11) as the current system version which is used by the install script below.
Failure to do so may result in problems installing Python dependencies.

# Set up the environment

Jade requires the esp-idf sdk.

More information is available in the [Espressif official guide](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32/get-started/index.html).

Get the esp-idf sdk and required tools:

```
mkdir ~/esp
cd ~/esp
git clone -b v5.4 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
git checkout 67c1de1eebe095d554d281952fde63c16ee2dca0
./install.sh --enable-gdbgui esp32 esp32s3
python ./tools/idf_tools.py install qemu-xtensa
```

Set up the idf environmental and make the `idf.py` command available:

```
. $HOME/esp/esp-idf/export.sh
```

# Devices

There are currently three Jade device targets:
- jade: The original Jade 1.0 with a selection wheel.
- jade_v1_1: Jade 1.1, which has a rocker/jog-wheel in place of the selection wheel.
- jade_v2: Jade Plus, with a larger screen and left/right selection buttons in place of a wheel or rocker.

Change `jade` in any calls to the `switch_to.sh` script below to the
appropriate device you wish to target from the list above.

# Serial port

The serial port pseudo-tty file for Jade access via USB is usually `/dev/ttyACM0` or `/dev/ttyUSB0`, or `/dev/cu.SLAB_USBtoUART` on MacOS. Note that the supplied docker-compose.yml assumes the Jade device is at /dev/ttyUSB0.

In order to have permission to use USB to install firmware, your user should be in `dialout` group on Debian
based distributions. Other distributions may use a different group name: Check the group of the serial
port pseudo-tty file using `ls -l` command to determine the required group, e.g:

```
$ ls -l /dev/ttyACM0
crw-rw----+ 1 root dialout 166, 0 Apr 15 14:37 /dev/ttyACM0
```

The group name (`dialout` here) is shown after the owner (`root`). You can check that `dialout` appears in your user groups by running:

```
$ groups
docker libvirt dialout storage kvm wheel plugdev
```

If not present you should add your user to the group:

```
sudo usermod -aG dialout $USER
```

You should then login/logout or reboot for the group changes to take effect.

# Build the firmware

First, you'll need the Jade source code including its sub-modules checked out:

```
git clone --recursive https://github.com/Blockstream/Jade.git $HOME/jade
cd $HOME/jade
git submodule update --init --recursive
```

Choose your configuration. For Jade development, the script `tools/switch_to.sh` allows
choosing the device and features you want. Run `tools/switch_to.sh --help` to see the
available options. A standard development Jade Plus build for example would use something
like:

```
./tools/switch_to.sh jade_v2 --dev --log --jtag [--noradio]
```


For other devices, copy (and modify if desired) a suitable config from the `configs`
directory to `sdkconfig.defaults`. You should also run e.g. `idf.py set-target esp32` or
`idf.py set-target esp32s3` once initially to ensure you are targeting the correct
toolchain for your hardware. So for example for the TTGO T-Display:

```
cp configs/sdkconfig_display_ttgo_tdisplay.defaults sdkconfig.defaults
```

To build the firmware, run:

```
idf.py all
```

To flash the resulting build to your device, run:

```
idf.py flash [monitor]
```

Some hardware configurations (e.g. M5StickC-Plus) may not support the default baud
rate and so won't be detected. If this occurs you can force a specific baud rate
for flash/monitor by using the `-b` argument, e.g:

```
idf.py -b 115200 flash monitor
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
idf.py menuconfig
```

Note: for any but the simplest CI-like build with no GUI, no camera, no user-interaction etc. it is recommended that PSRAM is available and enabled.  ( Component Config -> ESP-32 specific -> Support external SPI connected RAM )

# Run the tests

Virtualenv and bluez-tools are required, you can install them on Debian based distributions with:

```
sudo apt install virtualenv bluez-tools
```

Then to run the tests:

```
cd $HOME/jade
virtualenv -p python3 venv3
source venv3/bin/activate
pip install -r requirements.txt
pip install -r pinserver/requirements.txt

python test_jade.py

deactivate
```

Note that the tests require a CI build; this is a configuration that automatically
accepts the default action without requiring user interaction. This is enabled using
the `--ci` argument to `switch_to.sh` or by setting `CONFIG_DEBUG_UNATTENDED_CI=y`
in sdkconfig.defaults.

Debug support is also required to expose debug functions for testing. Use `--debug`
or set `CONFIG_DEBUG_MODE=y` to enable this.

# Use docker

If you are on MacOS, you are better off setting up the environment locally as detailed above, rather than trying to get access to your device from the docker container. For more, see [this article](https://dev.to/rubberduck/using-usb-with-docker-for-mac-3fdd).

The supplied docker-compose.yml assumes the Jade device is at /dev/ttyUSB0, but note that it may instead be e.g. /dev/ttyACM0 (or have another numeric suffix or path depending on the host operating system).

The build steps within docker are the same as detailed above, e.g:

```
(local)$ docker-compose up -d
(local)$ docker-compose exec dev bash
(docker)$ ./tools/switch_to.sh jade --dev --log --jtag [--noradio]
(docker)$ idf.py all
(docker)$ idf.py flash
```

The docker-compose.yml also mounts the local git repository so that it is the
origin of the repository in the docker.


# Emulator/Virtualizer (qemu in Docker)

The following will build a docker image running the headless ci-test (approves every request):

```
docker build -t jade-qemu-ci -f Dockerfile.qemu .
docker run --rm -p 30121:30121 -it jade-qemu-ci
```

The python 'jadepy' API can talk to it as if it were a serial interface, if given the device string 'tcp:localhost:30121'.

```
python -c "from jadepy.jade import JadeAPI; jade = JadeAPI.create_serial(device='tcp:localhost:30121'); jade.connect(); print(jade.get_version_info()); jade.disconnect()"
```

Similarly, for a manually driven web-enabled 'virtual jade' (at 'http://localhost:30122/'):

```
docker build -t jade-qemu-web -f Dockerfile.qemu --build-arg="SDK_CONFIG=configs/sdkconfig_qemu_psram_webdisplay.defaults" .
docker run --rm -p 30121:30121 -p 30122:30122 -it jade-qemu-web
```

Alternatively, to run the qemu emulator with display and camera support, run:

```
main/qemu/run_emulator.sh [--larger-display]
```

Open a web browser and point it to 'http://localhost:30122' to interface with the emulated Jade.

Note that the ```run_emulator.sh``` command will launch a docker image so it will only work on Linux.

Otherwise if you don't need the display or want to run with gdb, follow the below steps.

Run these commands inside the jade source repository root directory to enter a docker container:

```
DOCKER_BUILDKIT=1 docker build . -t testjadeqemu
docker run -v ${PWD}:/jade -p 30121:30121 -it testjadeqemu bash
```

Note: You can skip the build step if you want by fetching the pre-built image and running with

```
docker pull blockstream/verde
docker run -v ${PWD}:/jade -p 30121:30121 -it blockstream/verde bash
```

Inside the container, run:

```
. /root/esp/esp-idf/export.sh
cd /jade
rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all
cp components/esp32_bsdiff/bsdiff.* build/
apt-get update -qq && apt-get install virtualenv -yqq
virtualenv -p python3 ./venv3
source ./venv3/bin/activate
pip install -r requirements.txt
./tools/fwprep.py build/jade.bin build
./main/qemu/make-flash-img.sh

# To run the CI tests
./main/qemu/qemu_ci_flash.sh

# To reboot the qemu instance
./main/qemu/qemu_reboot.sh

# To reboot the qemu instance and attach gdb to the Jade fw
./main/qemu/qemu_gdb.sh

```
At this point the Jade fw running in the qemu emulator should be available on 'tcp:localhost:30121' from inside and outside the docker container.

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
