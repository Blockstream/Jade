These scripts assume ubuntu. The following instructions are just high level,
for actual deployment/flashing use offline equipment and verification
of installed packages with signatures/hashes as needed.

Enable universe if not already enabled with `sudo add-apt-repository universe`

Install virtualenv with `sudo apt install virtualenv`

Now create our working directory `/tmp/jade`


`mkdir /tmp/jade`


Now create a virtualenv with `virtualenv -p python3 /tmp/jade/venv`
and install the required packages

```
source /tmp/jade/venv/bin/activate
pip install -r /tmp/jade/flashing/requirements.txt
deactivate
```

The directory `flashing` in the root and `build` from the CI pipeline has to be put in the `/tmp/jade` directory.

The file `99-jade-flasher.rules` from `/tmp/jade/flashing` has to be put in the `/etc/udev/rules.d` directory

```
sudo cp /tmp/jade/flashing/98-jade-flasher.rules /etc/udev/rules.d/98-jade-flasher.rules
sudo cp /tmp/jade/flashing/99-jade-flasher.rules /etc/udev/rules.d/99-jade-flasher.rules
chmod +x /tmp/jade/flashing/*.sh
```

Then you need to reload udev rules with

```
sudo udevadm control --reload-rules
sudo udevadm trigger
```

from now on when a Jade is connected the script `/tmp/jade/flashing/flash.sh` will run and the env var `${DEVNAME}`
will be set to the ttyUSB* device, for example `/dev/ttyUSB0`

You can set `FLASHROOT=${HOME}/YOUR/DIRECTORY` to test the script manually from a different directory than `/tmp/jade`
and `DEVNAME=/dev/ttyUSB0` for example.

During flashing you can `tail /tmp/jade/jadeflash.log` to see the result of detection and bootloader and app flashing.
When a device is fully flashed you will see the message "Flashing complete for " followed by a ttyUSB* device name.

Note: You may have to uninstall or disable modemmanager to avoid concurrent access to the device and flashing failures, for example
```
sudo apt remove modemmanager
```

Note: As an alternative to the udev rules you can also instead run a simple inotify based bash script
Warning: if you run this at the same time as the udev rules concurrent access to the devices may occur and flashing failure as a consequence

First, install the inotify-tools if not already installed
```
sudo apt install inotify-tools
```

The script would look like (replace in the script below ACM with USB as needed)
```
#!/usr/bin/env bash
set -eo pipefail
export FLASHROOT=/tmp/jade
while read i; do if [[ "$i" == ttyACM* ]]; then DEVNAME=/dev/${i} ${FLASHROOT}/flashing/flash_jade.sh; fi; done < <(inotifywait  -e create --format '%f' --quiet /dev --monitor)
```
