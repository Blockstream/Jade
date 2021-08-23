# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

### Changed

### Fixed

## [0.1.27] - 2021-08-30
### Added
- Enable creation of new 12-word recovery phrase
- Method to export liquid master blinding key, after user confirmation
- Add support for testnet-liquid network

### Changed
- Update liquid asset info
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
- Update liquid asset info
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
- Update liquid asset info
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
- Update liquid asset info
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
- Update liquid asset info
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
