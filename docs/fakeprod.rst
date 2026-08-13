================
Fakeprod firmware
================

``--fakeprod`` is a development-only build mode that reproduces a production
Jade v2 firmware as closely as possible (secure boot + flash encryption)
while remaining easily flashable for devs.

.. warning::

    Fakeprod builds are **NOT secure** and must never be used on a real wallet.
    The signing key is committed to the repository, the bootloader accepts a
    single signature, ROM download mode and JTAG are left enabled, and the
    flash-encryption key stays readable.

Usage
=====

.. code-block:: bash

    # Configure the build. Add --jtag to also get a USB-JTAG serial console.
    ./tools/switch_to.sh jade_v2 --fakeprod --jtag

    # Build (auto-signed with the committed key).
    idf.py all

    # First-time provisioning:
    idf.py flash            # app + partition table + otadata, plaintext
    idf.py bootloader-flash # the signed bootloader (not flashed automatically)

    # Power-cycle the unit and wait a bit (on first boot the
    # bootloader enables secure boot, generates the flash-encryption key,
    # encrypts the flash in-place, and resets)

    # Subsequent updates (pre-encrypted on the host; see "Re-flashing" below).
    idf.py encrypted-flash

Differences from production
===========================

.. list-table::
   :header-rows: 1

   * - Setting
     - Production
     - Fakeprod
   * - ``CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES``
     - ``n`` (signed offline by release keys)
     - ``y``
   * - ``CONFIG_SECURE_BOOT_SIGNING_KEY``
     - unset
     - ``tools/fakeprod_v2.pem``
   * - ``CONFIG_SECURE_BOOT_V2_MIN_SIGNATURES``
     - ``2``
     - ``1``
   * - ``CONFIG_SECURE_FLASH_ENCRYPTION_MODE_*``
     - ``RELEASE``
     - ``DEVELOPMENT``
   * - ``CONFIG_SECURE_DISABLE_ROM_DL_MODE``
     - ``y``
     - removed (ROM download mode stays enabled)
   * - ``CONFIG_SECURE_BOOT_ALLOW_JTAG``
     - unset
     - ``y``
   * - ``CONFIG_JADE_FAKEPROD``
     - unset
     - ``y``
   * - ``CONFIG_DEBUG_MODE``
     - unset
     - ``y``

Everything else (secure boot v2, anti-rollback, flash encryption enabled,
PSRAM settings, and so on) is inherited unchanged from the production config,
so the app's profile matches production as closely as possible.

Signing key
===========

``tools/fakeprod_v2.pem`` an in-tree, non-secret key

Because ``CONFIG_SECURE_BOOT_V2_MIN_SIGNATURES`` is set to ``1`` you can
reflash using ESP-IDF tools directly

First-boot eFuse programming
============================

Because secure boot is enabled, the build does **not** flash the bootloader
automatically (``idf.py flash`` and ``idf.py encrypted-flash`` skip it, to
avoid accidentally bricking a secure-boot device). Flash it manually once:

.. code-block:: bash

    idf.py bootloader-flash

On the next boot the bootloader performs one-time provisioning:

1. enable secure boot v2 (burn the key digest and ``SECURE_BOOT_EN``);
2. generate and burn the flash-encryption key;
3. encrypt the flash in-place (this can take up to a minute);
4. reset.

If you flash the app but not the bootloader, the app aborts shortly after
``spi_flash`` init because ``CONFIG_SECURE_FLASH_CHECK_ENC_EN_IN_APP`` detects
that flash encryption is not enabled, and the unit reboot-loops silently.

The following eFuses are burned on first boot (irreversible):

* ``SECURE_BOOT_EN`` - secure boot is enabled.
* ``DIS_DIRECT_BOOT``.
* Flash-encryption key and ``SPI_BOOT_CRYPT_CNT`` (development mode: the
  counter is neither maxed nor write-protected).
* ``DIS_DOWNLOAD_MANUAL_ENCRYPT``, ``DIS_DOWNLOAD_DCACHE`` and
  ``DIS_DOWNLOAD_ICACHE``.

These are the security features that are **not** disabled:

* ROM download mode is kept enabled so ``esptool.py`` can still connect.
* JTAG: ``HARD_DIS_JTAG`` / ``DIS_USB_JTAG`` are not burned.
* Flash-encryption key remains readable (``RD_DIS_BLK1`` is not burned).
* eFuses remain readable (``CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS=y``).

Re-flashing
===========

There are two ways to update a fakeprod unit

Encrypted (unlimited)
---------------------

In development mode the flash-encryption key stays readable, so:

.. code-block:: bash

    idf.py encrypted-flash

reads the key from the device, pre-encrypts the image on the host and writes
encrypted data. This never touches ``SPI_BOOT_CRYPT_CNT``, consumes no eFuse
bits and can be repeated indefinitely.

This only works **after** first-boot provisioning has programmed the key. On a
fresh unit it fails with ``Flash encryption key is not programmed``.

Plaintext (limited)
-------------------

Plaintext can only be written while encryption is off. Toggling encryption
uses the 3-bit ``SPI_BOOT_CRYPT_CNT`` eFuse which will be maxed out after
only a few toggles (shoud probably only use for reviving a bricked unit)

Attestation
===========

Fakeprod exercises the production attestation flow (``register_attestation`` /
``sign_attestation``) against a dedicated in-tree, non-secret authority key,
``tools/fakeprod_attest.pem`` (production validates against the real Jade
master attestation public key instead).

Because fakeprod always builds with ``CONFIG_DEBUG_MODE``, it uses a fixed
attestation HMAC key and does not burn ``WR_DIS_RD_DIS``, so attestation can
be **re-provisioned** as many times as needed on the same unit.

Initialise attestation (generates a fresh per-device RSA-4096 key, signs it
with the fakeprod authority key and sends it to the unit):

.. code-block:: bash

    python jade_attest.py --init-new tools/fakeprod_attest.pem

Verify attestation (asks the unit to sign a random challenge and checks the
result against the fakeprod authority public key):

.. code-block:: bash

    python jade_attest.py --verify tools/fakeprod_attest.pem

Notes
=====

* Label a dev unit once you have flashed it with fakeprod firmware, so you
  dont get confused when you try to reflash with incorrect firmware
* Anti-rollback stays enabled with ``CONFIG_BOOTLOADER_APP_SECURE_VERSION=2``,
  which is burned on first boot. Re-flashed images must therefore keep a
  secure version of at least 2.
* ``--fakeprod`` alone keeps ``CONFIG_ESP_CONSOLE_NONE=y`` (as in production).
  Add ``--jtag`` to enable the USB-JTAG serial console for debugging.
