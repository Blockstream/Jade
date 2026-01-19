# Updating the Firmware on a Blockstream Jade Unit

Blockstream Jade firmware is best updated via a Blockstream Green wallet application - available for Android, iOS, Windows, Mac and Linux.

The firmware can also be updated using a small script provided in this repo, as below.

NOTE: Blockstream Jade units will only run firmware signed by Blockstream, therefore it is not possible to build and flash the firmware on a 'diy' basis.
The signed firmware must be downloaded from Blockstream servers, and can only be updated using the 'OTA' function of the currently installed firmware.

NOTE: To build and flash firmware for other supported esp32 devices - eg. M5Stack or TTGO T-Display, follow the developers instructions in the main README.md.


# Method 1 - Download and Update - One Step

The Jade unit should be switched on, and connected via a good quality USB data cable.
Run the update script - this will inspect the connected Jade to determine its hardware type/revision, and should then display a list of available firmwares appropriate for the connected device.
```
./update_jade_fw.py
```
By default the latest stable release is fetched - it is possible to fetch older/previous versions, or indeed beta versions, using the `--release` option.
NOTE: downgrading to a previous version once a wallet has been setup on the device with a later version is not recommended.
Firmware deltas are listed before full firmware images - deltas are much smaller and faster to fetch and upload and so are usually preferred.

Select the firmware to fetch.  This should then be downloaded.

When asked whether to save a local copy of the firmware file, answer 'n' as this is unnecessary.

When asked whether to upload this file to the connected Jade unit - answer 'y'.

The update should then commence - confirmation is required on the Jade hardware, and the update should then should proceed to completion.
The Jade unit should restart and boot the updated firmware.


# Method 2 - Download and Update - Two Separate Steps

As above - run the script and select the firmware to fetch.
```
./update_jade_fw.py
```

When asked whether to save a local copy of the firmware file, answer 'y' - a copy of the firmware will be written to the current directory.  A .hash file containing the hex hash of the final firmware may also be written.

When asked whether to upload this file to the connected Jade unit - answer 'n' - the script should exit.

The sha256 hash of the file can then be checked, and if desired the downloaded file can be verified against the source code in this repo (given the appropriate tag/config) - see REPRODUCIBLE.md.

NOTE: if a .hash file is also written, this contains the hash of the final uncompressed firmware - in the case of a delta this hash refers to the complete firmware image obtained by applying the delta to the firmware currently running in the Jade unit.

This local file can then be uploaded to the Jade hardware as follows:
```
./update_jade_fw.py --fwfile <path to file>
```
NOTE: the filename must be unchanged from what was downloaded.

You will be asked whether to upload this file to the connected Jade - answer 'y' and confirm on the Jade unit.
The update should then run to completion and the Jade should reboot the updated firmware.


# Troubleshooting:

The Blockstream Jade unit must be connected and switched on as the script tries to communicate with it - the script will error if no Jade is connected or may hang indefinitely if the Jade is connected but not switched on, or is in the process of some other action (eg. showing an address, signing a message or transaction, etc.)

By default the usb/serial connector tries to use device /dev/ttyUSB0 - this may need to be changed to eg. /dev/ttyACM0 or some other location as appropriate for the o/s platform and driver in use.  In which case, the `--serialport` option can be used.

More verbose logging can be accessed using the `--log` option.
