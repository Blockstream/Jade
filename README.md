# Jade Firmware

NOTE: the below instructions are for Jade developers with access to Jade development boards or for those wanting to build and flash their own esp32 consumer devices - eg. M5Stack or TTGO T-Display boards.
They are not for updating the firmware of an official Blockstream Jade hw unit - these can only be updated in-app, or using the 'update_jade_fw.py' script - see FWUPDATE.md

* DO NOT ATTEMPT THE BELOW WITH BLOCKSTREAM OFFICIAL BLOCKSTREAM JADE HW UNITS

To build you can use the docker image (see Dockerfile) or install the esp-idf toolchain and repo following the commands in this readme.

# Use docker

Note the supplied docker-compose.yml assumes the Jade device is at
dev/ttyUSB0.

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

More information is available in the [Espressif official guide](https://docs.espressif.com/projects/esp-idf/en/v4.4.1/esp32/get-started/index.html).

Get the esp-idf sdk and required tools:

```
cd ~/esp
git clone -b v4.4.1 --recursive https://github.com/espressif/esp-idf.git
cd ~/esp/esp-idf && git checkout 1329b19fe494500aeb79d19b27cfd99b40c37aec && ./install.sh esp32
```

Set up the environmental variables:

```
. $HOME/esp/esp-idf/export.sh
```

# Build the firmware

```
git clone --recursive https://github.com/Blockstream/Jade.git $HOME/jade
cd $HOME/jade
cp configs/sdkconfig_jade.defaults sdkconfig.defaults
idf.py flash monitor
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

Run these commands inside the jade source repo root directory, it will enter a docker container

```
DOCKER_BUILDKIT=1 docker build . -t testjadeqemu
docker run -v ${PWD}:/jade -p 2222:2222 -it testjadeqemu bash
```

Note: You can skip the build step if you want by fetching the prebuilt image and running with

```
docker pull blockstream/verde
docker run -v ${PWD}:/jade -p 2222:2222 -it blockstream/verde bash
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
At this point the Jade fw running in the qemu emulator should be available on 'tcp:localhost:2222' from inside and outside the docker container.

# License

The collection is subject to gpl3 but individual source components can be used under their specific licenses.
