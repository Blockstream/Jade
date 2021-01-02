
Test configs to test flash encryption and secure boot.

** BURNS EFUSES SO DO NOT USE UNLESS YOU'RE SURE
** ie. these are is one-way configs that cannot be disabled once enabled.
**     Changes the hw unit for good.  There is no comong back from these!

** I beleive the below are mutually exclusive / not interchangable - you can't 'promote' 1. into 2.

# To see key config changes diff the file of interest against
../configs/sdkconfig_jade.defaults
and/or:
../production/sdkconfig_jade_prod.defaults

Use:
Probably best to do a full clean build:

From root jade dir:
  rm sdkconfig
  cp test_configs/<file> ../sdkconfig.defaults
  idf.py erase_flash
  idf.py fullclean build


1. Flash and NVS Encryption (dev [re-flashable] mode)
https://docs.espressif.com/projects/esp-idf/en/release-v4.1/security/flash-encryption.html

flash_and_nvs_encrypt.defaults

Once this has been done all subsequent flashes will have to be with a 'flash encryption' config, and flashed with 'idf.py encrypted-flash'
ie.
first flash:
  idf.py flash monitor
all subsequent:
  idf.py encrypted-flash monitor


2. Secure boot (v2[RSA]) with Flash and NVS Encryption (release [not re-flashable] mode)
https://docs.espressif.com/projects/esp-idf/en/release-v4.1/security/secure-boot-v2.html

secure_boot_with_flash_and_nvs_encrypt.defaults

After the build - check:
  ls -l build/bootloader

Check bootloader.bin exists and size is below the limit (~27.5k)
(A smaller bootloader-unsigned.bin should also exist.)

The build should have output a banner similar to the below:
>
==============================================================================
Bootloader built. Secure boot enabled, so bootloader not flashed automatically.
Secure boot enabled, so bootloader not flashed automatically.
	/mnt/data/blockstream/venv/jade/bin/python /mnt/data/blockstream/esp/esp-idf/components/esptool_py/esptool/esptool.py --chip esp32 --port (PORT) --baud (BAUD) --before default_reset --after no_reset write_flash --flash_mode dio --flash_freq 40m --flash_size 4MB  -u 0x1000 /mnt/data/blockstream/jade/build/bootloader/bootloader.bin
==============================================================================
<

Execute the command-line it has suggested, with relevant PORT (can be omitted if default ok) and BAUD (115200 is fine as bootloader is small).
(needs manual confirmation)

Then flash the application:
  idf.py flash

** NOTE: any subsequent app upgrades will have to be done via OTA (eg. the jade_ota.py script).
  python fwprep.py ; python jade_ota.py --skipserial

Boot ... :
  idf.py monitor



