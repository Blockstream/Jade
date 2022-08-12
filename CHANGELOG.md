# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

### Changed

### Fixed

## [0.1.35] - 2022-08-11
### Added
- Add 'wallet-erase' duress pin
- Add support for HOTP and TOTP code generation, including passing current UTC time to Jade
- Support scan and import/recovery of SeedSigner QR codes
- Added message fields to be able to pass asset registry data when signing a Liquid transaction

### Changed
- Update Liquid asset registry info
- Update ESP-IDF base firmware to v4.4.2
- Changed how to specify when to enter a BIP39 passphrase
- Updated QR scanning - much faster and no need to press front button to scan
- Settings menu items rearranged, and added pre-PIN Settings menu

### Fixed
- Fixed issue when scanning QR of mnemonic that contains valid words which are prefixes of other valid words
- Reduce memory usage in UI screens
- Fixed incorrect error code/id returned if firmware update fails
- Internal code improvements

## [0.1.34] - 2022-05-27
### Added
- Add support for generic multisig on liquid and remove requirement on deterministic blinders and commitments hmac
- Show battery icon in orange/red when charge level low/very-low

### Changed
- Update Liquid asset registry info
- Update ESP-IDF base firmware to v4.4.1
- Increase max supported BIP39 passphrase length to 100 characters
- QR mnemonic scan accepts unambiguous word prefixes
- Refactor OTA and OTA-delta to use a common submodule to wrap the fw decompress

### Fixed
- Fixed occasional ephemeral 'low battery' icon when battery charged/charging
- Fixed rare/intermittent failure to start camera
- Always send rejection message when receive buffers stale or overflowed
- Reduce memory usage and memory fragmentation
- Internal code-consistency improvements

## [0.1.33] - 2022-03-03
### Added
- Support for OTA by delta, rather than uploading entire firmware image
- Add RPC/CBOR message documentation, and add docstrings to jadepy client
- Add support for SSH and GPG keys and signing, for curve nist256p1/secp256r1
- Add testnet-liquid assets
- Display of OP_RETURN outputs
- Generate non-confidential liquid addresess, and support signing non-confidential inputs
- Display warning if multisig path suffixes differ
- Add info screen showing storage usage

### Changed
- Update Liquid asset registry info
- Update ESP-IDF base firmware to v4.4.0
- Increase allowed multisig configurations to include from 1of1 to nof15
- Increase number of allowed multisig registrations from 8 to 16
- Improve 'out of storage space' reply and on-screen message when saving multisig record
- Make Python API BLE dependencies an optional/extra in setup.py
- Change wallet initialisation to store entropy rather than wallet master key

### Fixed
- Fix progress-bar screen flicker
- Reliability improvements reading input messages, esp. over serial
- Do not error on number of persisted multisig records when updating an existing record

## [0.1.32] - 2021-12-23
### Added

### Changed
- Update Liquid asset registry info

### Fixed
- Fix crash reported after entering passphrase with v0.1.31

## [0.1.31] - 2021-12-03
### Added
- Show current running firmware version on initial connection screens
- Add support for BIP67 sorted-multisig
- Add compressed file hash when uploading firmware in OTA process - currently optional but will be made mandatory in a future release
- Add battery status in version-info data, so companion apps can display Jade's approximate charge level
- Ensure Bech32m/P2TR transaction output addresses are displayed properly when signing
- Add flag to 'get_shared_nonce' call to also return the public blinding key, to avoid needing to make a second roundtrip
- Add flashing support for alternative hardware serial/USB chip CH9102

### Changed
- Update Liquid asset registry info
- Refactor internal tasks and GUI updating and event handling
- Update ESP-IDF base firmware to v4.3.1
- Update Libwally to 0.8.4 and use 'minimal build' flag to reduce size of binary and static memory footprint

### Fixed
- Fix issues with Bluetooth bonding to support multiple Jade devices
 * NOTE: THIS WILL INVALIDATE ALL CURRENTLY SAVED BLUETOOTH BONDS - DEVICES WILL NEED TO BE RE-PAIRED
- Fix Python API compatability issues with python version 3.10
- Fix font issues with some punctuation characters when displaying BIP39 passphrase
- Reset network restrictions when using temporary/emergency wallet

## [0.1.30] - 2021-10-20
### Added
- Support for generic multisig, following registration/approval of the multisig descriptor
- Support for bip39 passphrase, if selected during wallet initialisation/setup
- On-screen warnings for unexpected bip32 paths when generating addresses and when validating change addresses

### Changed
- Update Liquid asset registry info
- Make 'requests' module an optional dependency for the python api
- Remove returning a root certificate for the default pinserver
- Update policy asset and address prefixes for testnet-liquid network
- Remove 'regtest' as a network synonym for 'localtest' in Jade API
- Update qemu version, including adding support for spiram emulation

### Fixed
- Fix issue where Jade v1.1 jog-wheel appears to be stuck down in certain conditions when connected via Bluetooth
- Error earlier when insufficient/incorrect commitments passed to sign-liquid-tx
- Improve reliability of OTA, especially when running over BLE
- Fix path in script executing qemu in docker image

## [0.1.27] - 2021-08-30
### Added
- Enable creation of new 12-word recovery phrase
- Method to export liquid master blinding key, after user confirmation
- Add support for testnet-liquid network

### Changed
- Update Liquid asset registry info
- Update libwally to 0.8.3
- Update esp-idf base firmware to v4.2.2

### Fixed
- Improve performance and reliability when receiving large messages (eg. sign-liquid-tx) over Bluetooth
- Potential issue where derived key may not be zero'd in memory after failure
- Fixed corner-case issue reading long strings from cbor messages
- Derive liquid blinding factors consistently with Ledger
- Reduced memory usage for no-PSRAM hardware

## [0.1.26] - 2021-07-01
### Added
- Enable repeating next/prev events when jog-wheel (btn on M5Stack) held down
- Support firmware download for new Jade hardware in 'jade_ota.py' script
- Added '(Temporary Wallet)' to 'Ready!' screen, if using temporary restore wallet
- Added screens to show legal certification text and icons as required

### Changed
- Update Liquid asset registry info
- Setup screens to use 'recovery phrase' wording rather than 'mnemonic'
- At boot, delay powering screen backlight until splash screen image ready

### Fixed
- Corrected detecting USB connected on new Jade hardware
- Fixed assert when trying to display large amount strings when signing
- Do not allow wiping Bluetooth bonding data when Bluetooth disabled
- Fixed detecting when Jade disconncted from companion app when entering PIN or signing tx etc.

## [0.1.25] - 2021-06-11
### Added
- New Emergency Restore / Temporary Wallet - can be used without persistence or pinserver interaction
- New 'offline' setup of Jade wallet/mnemonic, tweaks to setup screens
- Add support for user-set bespoke pinserver
- Add support for new Jade hardware
- Add support for running under QEMU emulator
- Add configs for M5stack basic/core, and TTGO-TDisplay boards

### Changed
- Update Liquid asset registry info
- Update default pinserver certificate
- Prefer 'Bluetooth' to 'BLE' in button labels, and use official bluetooth icon
- Use larger font when entering PIN
- 'Sign message' screen to prefer showing the message text, rather than the hash

### Fixed
- Tests running on no-PSRAM devices
- Do not try to access camera on hw boards which do not have one

## [0.1.24] - 2021-04-14
### Added
- Add locked-state and network-restriction to 'get_version_info' reply data
- Have 'auth_user()' call return immediately if passed inappropriate network
- Add support for 'Anti-Exfil' signatures in Jade
- Enable wallet recovery using 12-word mnemonic
- Support for single-sig transaction signing and address generation

### Changed
- Update Liquid asset registry info
- Update libwally to 0.8.2 and include libsecp's S2C module
- When several screens to scroll through, set the 'Next' button as default
- Separate jadepy communications backends into modules
- Use larger font when displaying new mnemonic words

### Fixed
- Add dependencies missing from `setup.py`
- When signing always require prevout script to be passed explicitly
- Do not show backspace '<' when entering first digit of pin
- Fix CMakeLists.txt for autogen-lang files.

## [0.1.23] - 2021-02-01
### Added
- Extend 'jade_ota.py' script to be able to download and flash current beta fw version
- Added board-type to 'get_version_info' reply data
- Only accept requests over the connection which authenticated the user/verified the PIN
- Lock Jade when serial or BLE is connected or disconnected (ie. so user must re-enter PIN)

### Changed
- Update Liquid asset registry info
- If enter incorrect pin, 'auth_user()' call returns false rather than string
- Minor improvements to mnemonic entry screen
- Move pinserver out to its [own repo](https://github.com/Blockstream/blind_pin_server)
- Update libwally to 0.8.1

### Fixed
- Fixed issue sending to a legacy (1xxxx) address
- Show 'No Address' when confirming outputs with no scriptpubkey
- Return 'BAD_PARAMS' error when tx data missing from 'sign-msg' request
- Return 'BAD_PARAMS' error when tx input amounts insufficient to cover outputs
- Fixed GPIO conflict on M5Stack devices that caused issue with Button-A
- Fixed memory leak when using camera to scan qr codes
- Fixed skipping words if scroll backwards when confirming mnemonic word

## [0.1.21] - 2021-01-04
### Added
- Initial release of Blockstream Jade firmware
- Support for Green multisig wallet
- Supports btc and liquid

### Changed

### Fixed
