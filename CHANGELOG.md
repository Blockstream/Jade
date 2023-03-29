# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

### Changed

### Fixed

## [0.1.47] - 2023-02-29
### Added

### Changed
- Change sign_psbt api call to take 'network', consistent with other signing calls

### Fixed
- Corrected the config flag which controls persisting BLE pairings in NVS

## [0.1.46] - 2023-03-23
### Added
- Allow the hash of the final firmware image to displayed and verified during OTA
- Allow the signing of non-trivial PSBTs passed over the CBOR messaging interface by splitting the reply over multiple messages

### Changed
- Performance improvements, notably around scanning a Recovery Phrase and unlocking Jade with a PIN
- Change the way the hash hex is displayed during OTA
- Rename 'Passphrase Settings' button and screen to 'BIP39 Passphrase'
- Make final commitments optional in sign_liquid_tx message, if they are already present in the txn data
- Extend existing change validation to be able to run on any wallet output
- Update ESP-IDF base firmware to v5.0.1
- Update libwally to a master commit which supports using mbedtls for sha calculations
- Changes to remove some dependencies to reduce fw binary size
- Update jade_ota.py in line with update_jade_fw.py

### Fixed
- Addressed out-of-memory issue when scanning large PSBTs consisting of many QR frames
- Improved internal type consistency strictness

## [0.1.45] - 2023-02-22
### Added
- Added option to unlock Jade with PIN using only QR codes (ie. airgapped)
- Added bip85 creation of bip39 mnemonic phrase

### Changed
- Reworked initial screens and settings/options menus
- Handle truncating long multisig wallet names when scanning QR multisig setup
- Added more visible warning when offering bip39 passphrase use
- Update libwally to 0.8.8

### Fixed
- Fixed text widths in update_jade_fw.py script when loading alpha or beta fw

## [0.1.44] - 2023-02-13
### Added

### Changed
- Removed unused camera support from build configs

### Fixed

## [0.1.43] - 2023-02-10
### Added
- Facilitate bip39 passphrases made up only of wordlist words
- Add option to calculate the final bip39 mnemonic word
- Support sign-message via QR (eg. Specter)
- Add wallet 'logout' option to lock hw unit

### Changed
- Improved display of BTC output to avoid scrolling address string
- Update Liquid asset registry info
- Update ESP-IDF base firmware to v4.4.4
- Update esp32-camera library to v2.0.3

### Fixed
- Apply a minimum 'idle-off time' when scanning or displaying qr codes
- Fix pressing 'Scan' on a 'diy' esp32 device without a camera
- Fix display of multisig bech32 addresses in 'verify address' screen

## [0.1.42] - 2023-01-22
### Added
- Support QR import of multisig wallet via common format
- Support scanning and verifying registered multisig receive address QR
- Support change output detection and verification for registered multisig wallets
- Support scanning pinserver setup details via QR
- Support scanning current epoch time QR (for TOTP)
- Support scanning OTP setup QR directly from main 'Scan' page
- Show signer/wallet fingerprint on main 'Ready' screen

### Changed
- Update Liquid asset registry info
- Update libwally to 0.8.7, and to candidate 0.8.8 master commit
- Update ESP-IDF base firmware to v4.4.2
- qemu emulator port number changed from 2222 to 30121
- Update python tools to default to first detected unit, rather than ttyUSB0

### Fixed
- Show timeout value on button label in Settings->Device menu
- Respect any 'Use Passphrase' setting when using 'Recovery Phrase Login'

## [0.1.41] - 2022-11-09
### Added

### Changed

### Fixed
- Corrected path and script type in singlesig xpub export QR

## [0.1.40] - 2022-11-08
### Added
- Support scanning and signing txns using PSBTs and QR codes (ur:crypto-psbt)
- Support scanning and verifying a singlesig receive address QR
- Export a BIP44-like xpub using QR codes (ur:crypto-account)
- Support importing mnemonic in ur:crypto-bip39 format (vi QR)

### Changed
- Update Liquid asset registry info
- Update 'Settings' menus
- Update libwally to 0.8.6

### Fixed

## [0.1.39] - 2022-10-05
### Added
- Show BLE config of firmware during OTA

### Changed
- Update Liquid asset registry info
- Improved menu navigation 'back' button behaviour

### Fixed
- Fix internal error when connecting using 'Recovery Phrase Login'

## [0.1.38] - 2022-09-21
### Added
- Support scan and import/recovery of SeedSigner 'CompactSeedQR' codes
- Added screens to facilitate export (ie manual copy) of CompactSeedQR code
- Use camera when booting to feed image entropy into RNG

### Changed
- Update Liquid asset registry info
- Updated some UI strings
- Reduced some log levels in jadepy api

### Fixed
- Fix jadepy api issue where connection to qemu simulator did not respect passed timeout
- Internal code-quality improvements

## [0.1.37] - 2022-08-23
### Added
- Added 'Settings' menu for uninitialised Jade units

### Changed
- Update Liquid asset registry info
- Renamed 'Emergency Restore' to 'Recovery Phrase Login'
- Updated some UI strings and menu options

### Fixed
- Fix issue viewing multisig records introduced in v0.1.35
- Internal code-quality improvements

## [0.1.36] - 2022-08-17
### Added

### Changed
- Update Liquid asset registry info
- Display new mnemonic words in a column rather than a grid
- Updated some UI strings

### Fixed
- Fixed issue when entering OTP URI via the on-screen keyboard
- Fixed issue when OTA-delta fails patching

## [0.1.35] - 2022-08-11
### Added
- Add 'wallet-erase' duress pin
- Add support for HOTP and TOTP code generation, including passing current UTC time to Jade
- Support scan and import/recovery of SeedSigner 'SeedQR' codes
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
- Support for BIP39 passphrase, if selected during wallet initialisation/setup
- On-screen warnings for unexpected BIP32 paths when generating addresses and when validating change addresses

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
