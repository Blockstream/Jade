# Jade Firmware

NOTE: the below instructions are for Jade developers with access to Jade development boards or for those wanting to build and flash their own esp32 consumer devices - eg. M5Stack or TTGO T-Display boards.
They are not for updating the firmware of an official Blockstream Jade hw unit - these can only be updated in-app, or using the 'update_jade_fw.py' script - see FWUPDATE.md

* DO NOT ATTEMPT THE BELOW WITH BLOCKSTREAM OFFICIAL BLOCKSTREAM JADE HW UNITS

To build you can use the docker image (see Dockerfile) or install the esp-idf toolchain and repo following the commands in this readme.

# DIY Hardware & Programming Notes
For information about suitable DIY hardware, as well as suggested configuration profiles and notes on secure boot.
[DIY Guide](./diy/)

# Use docker

If you are on MacOS, you are better off setting up the environment locally (see next step) than trying to get access to your device from the docker container. For more, see [this article](https://dev.to/rubberduck/using-usb-with-docker-for-mac-3fdd).

Note the supplied docker-compose.yml assumes the Jade device is at /dev/ttyUSB0, but note that it may instead be /dev/ttyACM0 (or either with some other trailing number) or some other path as appropriate for the host operating system.

Note the below instructions assume an original Jade v1.0 hardware with a true wheel.
When using the later Jade v1.1 hw revision with a rocker/jog-wheel, use 'configs/sdkconfig_jade_v1_1.defaults' in place of 'configs/sdkconfig_jade.defaults'.
```
(local)$ docker-compose up -d
(local)$ docker-compose exec dev bash
(docker)$ cp configs/sdkconfig_jade.defaults sdkconfig.defaults
(docker)$ idf.py flash
```

The docker-compose.yml also mounts the local git repo so that it is the
origin of the repo in the docker.

# Set up the environment

Jade requires the esp-idf sdk.

More information is available in the [Espressif official guide](https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32/get-started/index.html).

Get the esp-idf sdk and required tools:

```
mkdir ~/esp
cd ~/esp
git clone -b v5.3.1 --recursive https://github.com/espressif/esp-idf.git
cd ~/esp/esp-idf && git checkout c8fc5f643b7a7b0d3b182d3df610844e3dc9bd74 && ./install.sh --enable-gdbgui esp32 esp32s3
```

Set up the environmental variables:

```
. $HOME/esp/esp-idf/export.sh
```

On MacOS: You will need cmake on your system for this step (`brew install cmake`).

If you encounter Python dependencies issue, make sure to use a recent Python version (e.g. Python 3.11) as the current system version which is used by the install script.

# Build dependencies

Cmake is needed to build the firmware, you can install in on debian based distros with:

``` 
sudo apt install cmake
```

# Serial port

In order to have permissions using serial port to load firmware, your user should be in `dialout` group on debian 
based distros, other distros can use a different group name, you can figure out by checking the group of the serial 
port 'file' using `ls -l` command:

(serial port is usually `/dev/ttyACM0` or `/dev/ttyUSB0`)

``` 
$ ls -l /dev/ttyACM0                                                                                                                     14:37:07
crw-rw----+ 1 root dialout 166, 0 Apr 15 14:37 /dev/ttyACM0
```

You can check that `dialout` appear in your user groups by running:

``` 
$ groups
docker libvirt dialout storage kvm wheel plugdev
```

if not present you should add your user to the group:

``` 
sudo usermod -aG dialout $USER
```

(you should then login/logout or reboot)

# Build the firmware

```
git clone --recursive https://github.com/Blockstream/Jade.git $HOME/jade
cd $HOME/jade
cp configs/sdkconfig_jade.defaults sdkconfig.defaults
idf.py flash monitor
```
Use a config file from the configs folder that is specific to your hardware (if available).

_For example for the TTGO T-Display:_
```
cp configs/sdkconfig_display_ttgo_tdisplay.defaults sdkconfig.defaults
```

If you flash multiple devices or make changes to the original config file that you used, make sure to delete the `sdkconfig` file that gets created from `sdkconfig.defaults`. Otherwise, your changes will not get picked up when building and re-flashing the firmware.

Some hardware configurations (eg: M5StickC-Plus) may not support the default baud rate and won't be detected, so you can force a specific baud rate for flash/monitor by using the `-b` argument.

_For example, the last line of the above code block would change be:_
```
idf.py -b 115200 flash monitor
```

# Build configurations

There are various build configurations used by the CI in the configs/ directory, which may be required for specific builds eg. without BLE radio, with the screen enabled (or disabled, as with the CI tests), or for specific hardware (eg. the m5-fire).

The menuconfig tool can also be used to adjust the build settings.

```
idf.py menuconfig
```
Note: for any but the simplest CI-like build with no GUI, no camera, no user-interaction etc. it is recommended that PSRAM is available and enabled.  ( Component Config -> ESP-32 specific -> Support external SPI connected RAM )

# Run the tests

```
cd $HOME/jade
virtualenv -p python3 venv3
source venv3/bin/activate
pip install -r requirements.txt

python test_jade.py

deactivate
```

# Emulator/Virtualizer (qemu in Docker)

The following will build a docker image running the headless ci-test (approves every request):
```
docker build -t jade-qemu-ci -f Dockerfile.qemu .
docker run --rm -p 30121:30121 -it jade-qemu-ci
```
The python 'jadepy' api can talk to it as if it were a serial interface, if given the device string 'tcp:localhost:30121'.
```
python -c "from jadepy.jade import JadeAPI; jade = JadeAPI.create_serial(device='tcp:localhost:30121'); jade.connect(); print(jade.get_version_info()); jade.disconnect()"
```

Similarly, for a manually driven web-enabled 'virtual jade' (at 'http://localhost:30122/'):
```
docker build -t jade-qemu-web -f Dockerfile.qemu --build-arg="SDK_CONFIG=configs/sdkconfig_qemu_psram_webdisplay.defaults" .
docker run --rm -p 30121:30121 -p 30122:30122 -it jade-qemu-web
```

Alternatively, to run the qemu emulator with display and camera support is to run
```
main/qemu/run_emulator.sh
```

Then you will be able to open the browser and point it to 'http://localhost:30122' to interface with the emulated Jade.

Note that the ```run_emulator.sh``` command will launch a docker image so it will only work on Linux.
You can also optionally pass the flag ```--larger-display``` to run the emulator with a bigger display.

Otherwise if you don't need the display or want to run with gdb, follow the below steps.

Run these commands inside the jade source repo root directory, it will enter a docker container:

```
DOCKER_BUILDKIT=1 docker build . -t testjadeqemu
docker run -v ${PWD}:/jade -p 30121:30121 -it testjadeqemu bash
```

Note: You can skip the build step if you want by fetching the prebuilt image and running with

```
docker pull blockstream/verde
docker run -v ${PWD}:/jade -p 30121:30121 -it blockstream/verde bash
```

Now inside the container

```
. /root/esp/esp-idf/export.sh
cd /jade
rm -fr sdkconfig
cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
idf.py all
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

Seen working on M5 Stack gray/black/FIRE, M5 Stick Plus, Core 2, Core S3, LilyGO T-Display, T-DisplayS3, RPI Zero + display shield (via QEMU), Desktop via Qemu (browser for display/webcam)

# Client

A python client is available to communicate with genuine or diy Jade units:
```
pip install jade-client
```
This installs the `jadepy` directory from this repo.  See [jade-client-requirements.txt](./jade-client-requirements.txt) and [jade-client-requirements.txt.asc](./jade-client-requirements.txt.asc)

# License

The collection is subject to gpl3 but individual source components can be used under their specific licenses.
