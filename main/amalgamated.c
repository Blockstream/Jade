#ifdef AMALGAMATED_BUILD
#undef AMALGAMATED_BUILD

#include <stdlib.h>
void __wrap_abort(void);
#define abort __wrap_abort

#define BUILD_ELEMENTS 1
#define BUILD_MINIMAL 1
#define HAVE_MBEDTLS_SHA256_H
#define HAVE_MBEDTLS_SHA512_H
#define ECMULT_WINDOW_SIZE 8
#define ENABLE_MODULE_ECDH 1
#define ENABLE_MODULE_ECDSA_S2C 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_RANGEPROOF 1
#define ENABLE_MODULE_RECOVERY 1
#define ENABLE_MODULE_SCHNORRSIG 1
#define ENABLE_MODULE_SURJECTIONPROOF 1
#define ENABLE_MODULE_WHITELIST 1
#define HAVE_BUILTIN_POPCOUNT 1
#include "../components/libwally-core/upstream/src/amalgamation/combined.c"

#include "./aes.c"
#include "./assets.c"
#ifdef CONFIG_IDF_TARGET_ESP32S3
#include "./attestation/attestation.c"
#endif // CONFIG_IDF_TARGET_ESP32S3
#include "./bcur.c"
#ifdef CONFIG_BT_ENABLED
#include "./ble/ble.c"
#endif // CONFIG_BT_ENABLED
#include "./camera.c"
#include "./descriptor.c"
#include "./display.c"
#include "./display_hw.c"
#include "./fonts/BigFont.c"
#include "./fonts/DefaultFont.c"
#include "./fonts/DejaVuSans18.c"
#include "./fonts/DejaVuSans24.c"
#include "./fonts/Retro8x16.c"
#include "./fonts/Sinclair_Inverted_M.c"
#include "./fonts/Sinclair_Inverted_S.c"
#include "./fonts/Sinclair_M.c"
#include "./fonts/Sinclair_S.c"
#include "./fonts/SmallFont.c"
#include "./fonts/Ubuntu16.c"
#include "./fonts/Various_Symbols_32x32.c"
#include "./fonts/battery_24x48.c"
#include "./fonts/comic24.c"
#include "./fonts/def_small.c"
#include "./fonts/jade_symbols_16x16.c"
#include "./fonts/jade_symbols_16x32.c"
#include "./fonts/jade_symbols_24x24.c"
#include "./fonts/minya24.c"
#include "./fonts/tooney32.c"
#include "./fonts/various_symbols.c"
#include "./gui.c"
#include "./identity.c"
#include "./idletimer.c"
#ifdef ESP_PLATFORM
#include "./input.c"
#endif // ESP_PLATFORM
#include "./jade_abort.c"
#include "./keychain.c"
#ifdef ESP_PLATFORM
#include "./logging.c"
#endif // ESP_PLATFORM
#include "./main.c"
#include "./multisig.c"
#include "./otpauth.c"
#include "./power.c"
#include "./process.c"
#include "./process/auth_user.c"
#include "./process/dashboard.c"
#include "./process/debug_clean.c"
#include "./process/debug_handshake.c"
#include "./process/debug_scan_qr.c"
#include "./process/debug_set_mnemonic.c"
#include "./process/get_bip85_entropy.c"
#include "./process/get_bip85_pubkey.c"
#include "./process/get_blinding_factor.c"
#include "./process/get_blinding_key.c"
#include "./process/get_commitments.c"
#include "./process/get_identity_pubkey.c"
#include "./process/get_identity_shared_key.c"
#include "./process/get_master_blinding_key.c"
#include "./process/get_otp_code.c"
#include "./process/get_receive_address.c"
#include "./process/get_registered_descriptor.c"
#include "./process/get_registered_descriptors.c"
#include "./process/get_registered_multisig.c"
#include "./process/get_registered_multisigs.c"
#include "./process/get_shared_nonce.c"
#include "./process/get_xpubs.c"
#include "./process/mnemonic.c"
#include "./process/ota.c"
#include "./process/ota_delta.c"
#include "./process/ota_util.c"
#include "./process/pinclient.c"
#include "./process/process_utils.c"
#include "./process/register_attestation.c"
#include "./process/register_descriptor.c"
#include "./process/register_multisig.c"
#include "./process/register_otp.c"
#include "./process/sign_attestation.c"
#include "./process/sign_bip85_digest.c"
#include "./process/sign_identity.c"
#include "./process/sign_message.c"
#include "./process/sign_psbt.c"
#include "./process/sign_tx.c"
#include "./process/sign_utils.c"
#include "./process/update_pinserver.c"
#ifdef CONFIG_ETH_USE_OPENETH
#include "./qemu/qemu_display.c"
#include "./qemu/qemu_tcp.c"
#endif // CONFIG_ETH_USE_OPENETH
#include "./qrcode.c"
#include "./qrmode.c"
#include "./qrscan.c"
#include "./random.c"
#include "./rsa.c"
#include "./selfcheck.c"
#include "./sensitive.c"
#ifdef ESP_PLATFORM
#include "./serial.c"
#endif // ESP_PLATFORM
#include "./signer.c"
#include "./smoketest.c"
#include "./storage.c"
#include "./ui/ble_confirm.c"
#include "./ui/camera.c"
#include "./ui/confirm_address.c"
#include "./ui/dashboard.c"
#include "./ui/descriptor.c"
#include "./ui/dialogs.c"
#include "./ui/keyboard.c"
#include "./ui/mnemonic.c"
#include "./ui/multisig.c"
#include "./ui/ota.c"
#include "./ui/otpauth.c"
#include "./ui/pin.c"
#include "./ui/qrmode.c"
#include "./ui/select_registered_wallet.c"
#include "./ui/sign_identity.c"
#include "./ui/sign_message.c"
#include "./ui/sign_tx.c"
#include "./ui/signer.c"
#include "./ui/update_pinserver.c"
#ifdef CONFIG_IDF_TARGET_ESP32S3
#include "./usbhmsc/usbhmsc.c"
#include "./usbhmsc/usbmode.c"
#endif // CONFIG_IDF_TARGET_ESP32S3
#include "./utils/address.c"
#include "./utils/cbor_rpc.c"
#include "./utils/event.c"
#include "./utils/network.c"
#include "./utils/psbt.c"
#include "./utils/shake256.c"
#include "./utils/temporary_stack.c"
#include "./utils/urldecode.c"
#include "./utils/wally_ext.c"
#include "./versioninfo.c"
#include "./wallet.c"
#include "./wire.c"
#endif // AMALGAMATED_BUILD
