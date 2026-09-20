# Waveshare ESP32 Devices

## S3 Touch LCD 2

The device uses touchscreen navigation and the BOOT button for sleep/wake.
Bluetooth is enabled by default but can be turned off with the NORADIO config
script.

## S3 Touch LCD 3.5

Same navigation model as the Touch LCD 2 (virtual touch buttons, BOOT button
long-press for sleep/wake). The camera plugs into the onboard DVP FPC
connector (the -C version ships with an OV5640 fitted). Battery charging and
level reporting are handled by the onboard AXP2101 PMU; an optional 3.7V
lithium battery can be attached to the MX1.25 header (check the connector
polarity before plugging it in). A long press of the PWR button (4s) cuts
power; when off on battery, the PWR button powers the device back on.

NOTE: the `3.5B` variant is a different device (QSPI display controller) and
is not supported.

## Flashing

To prepare the board for flashing, hold down the `BOOT` button and plug in the
USB at the same time.

### Enclosure

Please find CAD and 3D printing files
[here](https://github.com/trevarj/enclosures/tree/master/waveshare/ESP32-S3-Touch-LCD-2)
along with a BOM and useful notes.
