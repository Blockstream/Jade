import os
import sys
import time
import glob
import cbor2 as cbor
import copy
import json
import base64
import random
import logging
import math
import argparse
import subprocess
import threading
import _thread

import wallycore as wally
from jadepy.jade import JadeAPI, JadeError

LIQUID_DESCRIPTORS = True


# Enable jade logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jadepy.jade-device')
device_logger.setLevel(logging.DEBUG)
device_logger.addHandler(jadehandler)


def wait(seconds, force=False):
    if force or (not args.libjade and not args.spts):
        time.sleep(seconds)


def h2b(hexdata):
    if hexdata is None:
        return None
    elif isinstance(hexdata, list):
        return list(map(h2b, hexdata))
    elif isinstance(hexdata, dict):
        return {k: h2b(v) for k, v in hexdata.items()}
    else:
        return bytes.fromhex(hexdata)


def _h2b_additional_info(additional_info):
    for summary_item in additional_info['wallet_input_summary']:
        summary_item['asset_id'] = h2b(summary_item['asset_id'])
    for summary_item in additional_info['wallet_output_summary']:
        summary_item['asset_id'] = h2b(summary_item['asset_id'])


def _h2b_test_case(testcase):
    # Convert fields from hex to binary
    if 'txn' in testcase['input']:
        # sign-tx data
        testcase['input']['txn'] = h2b(testcase['input']['txn'])

        for input in testcase['input']['inputs']:
            if input:
                for k, v in input.items():
                    if k not in ['is_witness', 'path', 'sighash', 'satoshi', 'value']:
                        input[k] = h2b(v)

        if 'trusted_commitments' in testcase['input']:
            for commitment in testcase['input']['trusted_commitments']:
                if commitment:
                    for k, v in commitment.items():
                        commitment[k] = v if k == 'value' else h2b(v)

        if 'additional_info' in testcase['input']:
            _h2b_additional_info(testcase['input']['additional_info'])

        for k in ['expected_output', 'expected_legacy_output']:
            if k in testcase:
                testcase[k] = h2b(testcase[k])

    elif 'message' in testcase['input']:
        # sign-msg test data
        if 'ae_host_commitment' in testcase['input']:
            testcase['input']['ae_host_commitment'] = h2b(testcase['input']['ae_host_commitment'])
        if 'ae_host_entropy' in testcase['input']:
            testcase['input']['ae_host_entropy'] = h2b(testcase['input']['ae_host_entropy'])

        if 'expected_output' in testcase and len(testcase['expected_output']) == 2:
            testcase['expected_output'][0] = h2b(testcase['expected_output'][0])

    elif 'identity' in testcase['input']:
        # sign-identity test data
        testcase['input']['challenge'] = h2b(testcase['input']['challenge'])

        expected_output = testcase['expected_output']
        expected_output['slip-0013'] = h2b(expected_output['slip-0013'])
        expected_output['signature'] = h2b(expected_output['signature'])
        expected_output['slip-0017'] = h2b(expected_output['slip-0017'])
        expected_output['ecdh_with_trezor'] = h2b(expected_output['ecdh_with_trezor'])

    elif 'multisig_name' in testcase['input']:
        # multisig data
        descriptor = testcase['input']['descriptor']
        if 'master_blinding_key' in descriptor:
            descriptor['master_blinding_key'] = h2b(descriptor['master_blinding_key'])

        for signer in testcase['input']['descriptor']['signers']:
            signer['fingerprint'] = h2b(signer['fingerprint'])

        if 'blinding_key_tests' in testcase:
            for blinding_test in testcase['blinding_key_tests']:
                blinding_test['script'] = h2b(blinding_test['script'])
                blinding_test['their_pubkey'] = h2b(blinding_test['their_pubkey'])
                blinding_test['expected_blinding_key'] = h2b(blinding_test['expected_blinding_key'])
                blinding_test['expected_shared_nonce'] = h2b(blinding_test['expected_shared_nonce'])

        if 'commitments_tests' in testcase:
            for blinding_test in testcase['commitments_tests']:
                blinding_test['hash_prevouts'] = h2b(blinding_test['hash_prevouts'])
                blinding_test['asset_id'] = h2b(blinding_test['asset_id'])
                blinding_test['abf'] = h2b(blinding_test['abf'])
                blinding_test['vbf'] = h2b(blinding_test['vbf'])
                blinding_test['asset_generator'] = h2b(blinding_test['asset_generator'])
                blinding_test['value_commitment'] = h2b(blinding_test['value_commitment'])

    elif 'multisig_file' in testcase['input']:
        expected_result = testcase.get('expected_result')
        if expected_result and 'master_blinding_key' in expected_result:
            expected_result['master_blinding_key'] = h2b(expected_result['master_blinding_key'])

    elif 'descriptor_name' in testcase['input']:
        # descriptor data
        if 'multisig_equivalent' in testcase['input']:
            for signer in testcase['input']['multisig_equivalent']['descriptor']['signers']:
                signer['fingerprint'] = h2b(signer['fingerprint'])

    return testcase


# Helper to read a json file into a dict
def _read_json_file(filename):
    logger.info(f'Reading json file: {filename}')
    with open(filename, 'r') as json_file:
        ret = json.load(json_file)
        ret['filename'] = filename  # Add filename for debugging
        return ret


# Helper to read json test files into a list
def _get_test_cases(pattern, allow_sampling=True):
    filenames = [f for f in glob.glob('./test_data/' + pattern)]
    if args.json_filter:
        allowed_filenames = glob.glob('./test_data/' + args.json_filter)
        filenames = [f for f in filenames if f in allowed_filenames]
    if allow_sampling and filenames and args.sample_percent != 100:
        # Test only args.sample_percent percentage of the files, but
        # test all files if there are only a small number of them
        num_files = len(filenames)
        if num_files > 8:
            num_files = int(math.ceil((args.sample_percent / 100.0) * num_files))
            filenames = random.sample(filenames, num_files)
    return (_h2b_test_case(_read_json_file(f)) for f in filenames)


BLE_TEST_PASSKEYFILE = 'ble_test_passkey.txt'
BLE_TEST_BADKEYFILE = 'ble_test_badkey.txt'

# The default serial read timeout
DEFAULT_SERIAL_TIMEOUT = 240

# Time to wait for stale data timeout on device before sending follow-up message.
# The firmware stale-data timeout (wire.c TIMEOUT_TICKS) is 3s on v1.x and 2s on v2.x.
# This value must be > TIMEOUT_TICKS to reliably trigger the stale path.
STALE_DATA_TIMEOUT = 4

# The number of values expected back in version info
NUM_VALUES_VERINFO = 23
ESP32S3_CHIP_BOARDS = ['JADE_V2', 'JADE_V2C', 'TTGO_TDISPLAYS3', 'TTGO_TDISPLAYS3PROCAMERA',
                       'M5CORES3']

TEST_MNEMONIC = 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana'
# The seed resulting from TEST_MNEMONIC
TEST_MNEMONIC_SEED = \
    'f1d56befd46eddfc31cda129dc76cd4a2b41d2cf86f10a5ccf0787617afa3869' \
    '967aab0224742ccc002056747ea09b68598ddf79c027c37a7c3ec923004593da'


# NOTE: the best way to generate test cases is directly in core.
# You need to poke the seed below into the wallet as a base58 wif, as below:
# bitcoin-cli sethdseed true "92zRAmYnWVRrWJ6cQb8yrzEz9r3aXj4oEUiPAZEbiPKHpCnxkKz"
#
# NOTE: if using liquid you also need to import the master-blindingkey (which
# green/wally derives from the seed using slip77, but elements-core does not)
# elements-cli importmasterblindingkey
#                     "946549f3bb3fc7449a6e86908b3bf1cc19f50cbdd9c1c459632b7624b397aec1"
#
# To generate txns it'll need some funds!
# Get an address and mine over 100 blocks to that address to get some money
# in the wallet.  eg:
# bitcoin-cli generatetoaddress 120 2N8Yn3oXF7Pg38yBpuvoheDS7981vW4vy5b (for p2wsh-p2sh),
#                                   mwJDHFp93fuHZysBwU7RTiFXrJZXXcPuUc (p2pkh legacy) or
#                                   bcrt1qkrkcltr7kx5s5alsvnpvkcfunlrjtwx942zmn4 (p2wsh native)
#
TEST_SEED_SINGLE_SIG = 'b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c'

# The single-sig mnemonic used for test case generation.
# See the commit description adding this line for details of the
# resulting descriptors and multisig testing setup.
TEST_MNEMONIC_SINGLE_SIG = \
    'paddle puppy easily actor poet apart screen drastic city front predict damp'
# The seed resulting from TEST_MNEMONIC_SINGLE_SIG
TEST_MNEMONIC_SS_SEED = \
    '5eff11cb0a00759be57e20d20d8076b80e8954df54318967116269909b501c10' \
    '99c27239c6e1cc1e9211a9b8157f150d58fc3f88ba79fd7c1515f3f317732337'
# The master blinding key resulting from TEST_MNEMONIC_SINGLE_SIG
TEST_MNEMONIC_SS_MASTER_BLINDING_KEY = \
    'f5c572fce078ab45598b5c661395ee0bfe680a67704061151ad354d93170d187'

# NOTE: for get-xpub the root (empty path array) can be accessed (to allow
# external creation of watch-only public key tree)
# NOTE: networks 'liquid' and 'mainnet' result in 'xpub' prefix, else 'tpub'
GET_XPUB_DATA = [([], 'testnet', 'tpubD6NzVbkrYhZ4Y6YYLhPsm1vVhs7CDSvoxfTTohcN\
PigN2RkeMJL3gTWav9fCicJsC7eSyARLKi8Q3UU825cz65meRQFFfqTYfBBy3MHC6Vn'),
                 ([], 'mainnet', 'xpub661MyMwAqRbcGJMgtWQnZ6b8Nk1YE4RkR2sAT9ZE\
3ovUH95wH5UxY1qkg7aRC7MdQD7YMauTncJMMHyWdDmkCeKMMoVwzJoK5DbZHHhinUQ'),
                 ([], 'liquid', 'xpub661MyMwAqRbcGJMgtWQnZ6b8Nk1YE4RkR2sAT9ZE3\
ovUH95wH5UxY1qkg7aRC7MdQD7YMauTncJMMHyWdDmkCeKMMoVwzJoK5DbZHHhinUQ'),
                 ([0], 'localtest', 'tpubD9wHvxq4yutRJBbRis4guqLvvAZqppKmMJmqD\
i4HVtVRTRKKTMzomHx77PqcprGZf6UuzwiWn8QWbUx3ECSUStzMHFPJM2e16VUoqEGnkk7'),
                 ([6], 'localtest', 'tpubD9wHvxq4yutRaYSLLTxkMuSGafH6NyQMJeGhq\
sug25o2p9KMNqZAcSV1eYcX31eVXf5vS8MYUPp5Cr2HHAkmpgAHQHa7iG4bqW6ajLq6WVk'),
                 ([12, 123], 'localtest-liquid', 'tpubDBdwuiH7nSNmLs5ffMyv3jXv\
ZrqFgimAbxXvxhWgXWATBTYPjiBbEDRzanF6YBHCaPoMF8XJNJdsUeXZHBuy3tkUSbEYh3o1M6fEfM\
fdBV5'),
                 ([18, 986], 'mainnet', 'xpub6BYx1MizD2XPpY6EuF5Pso8cG5fVHJEWn\
iziGqXcrrcqH96MUiPcuNQkfKSnGx9tCvBJBZx35fiZE3zBbVkZqH89TU4W6HkyE9fSUx9QHNX'),
                 ([2147483651, 2147483648], 'mainnet', 'xpub69w5Svpcz1iNw383Q4\
dcKTH7DVwPinVYL8Ka7S61gskwY8SW4YeeCny4xdxhR9yFhPxGDJ9Yne8PNQFoqkVdUK2whQ9bJiZu\
MarKPtCixrX'),
                 ([2147483651, 2147483651], 'liquid', 'xpub69w5Svpcz1iP4ocLTZ9\
3HDnRkFwKRUomwEZwFuafNnDhTWirvUFxbtou6KQMT83gnyjZAKmsD8oTST6FTj5dgAZn5EP6KMPZw\
QGEQu1tqez'),
                 ([2147483692, 0, 1, 2], 'testnet-liquid', 'tpubDFHUCdwiKzeyST\
BkMyPec9y9VSwwVgn1AftmefpKLYTPrChSCTbHAnbXtSQTB8qEvR8H6nt3sBwNAUeYZK5oc75dWDiY\
WBrYcMRYW2DGU1Z')]

# Hold test data in separate files as can be large
MULTI_REG_TESTS = 'multisig_reg_*.json'
MULTI_REG_SS_TESTS = 'multisig_reg_ss_*.json'
MULTI_REG_FILE_TESTS = 'multisig_file_*.json'
MULTI_REG_BAD_FILE_TESTS = 'multisig_bad_file_*.json'

TEST_SCRIPT = h2b('76a9145f4fcd4a757c2abf6a0691f59dffae18852bbd7388ac')

EXPECTED_MASTER_BLINDING_KEY = h2b('afacc503637e85da661ca1706c4ea147f1407868c4\
8d8f92dd339ac272293cdc')

EXPECTED_BLINDING_KEY = h2b('023454c233497be73ed98c07d5e9069e21519e94d0663375c\
a57c982037546e352')

TEST_THEIR_PK = h2b('03e7cd9230b30bf53753a43add0e88931bac3be21baa4c6465d9f8da9\
251f2904c')

TEST_HASH_PREVOUTS_HEX = '95f17695f6329dbcce2aa0b7f1eaff823b19d64d8737d642d6e6\
147f5ec88342'

TEST_HASH_PREVOUTS = h2b(TEST_HASH_PREVOUTS_HEX)

TEST_REGTEST_BITCOIN = h2b('5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419\
ca290e0751b225')

EXPECTED_LIQ_COMMITMENT_1 = {'abf': h2b('42bc9c7025f3df490a208cb362ff220547910\
da1d3e81c63a6e7c28c3a33a993'),
                             'vbf': h2b('7a6693fde7b88efb8375db618670fb5ccb9b2\
f7e8743b7d772924f0426c5efe6'),
                             'asset_generator': h2b('0a5cf0a43ad404163946c28b8\
a36d0e5cb4895b0ee386da4cd1008ffc8cb464501'),
                             'value_commitment': h2b('082d8de9b7f66994abf789b2\
591738331f88a7ddbef4e553bbf123e47677d60099'),
                             'asset_id': h2b('5ac9f65c0efcc4775e0baec4ec03abdd\
e22473cd3cf33c0419ca290e0751b225'),
                             'value': 9000000}

EXPECTED_LIQ_COMMITMENT_2 = {'abf': h2b('a3510210bbab6ed67429af9beaf42f09382e1\
2146a3db466971b58a45516bba0'),
                             'vbf': h2b('6ec064a68075a278bfca4a10f777c730116e9\
ba02fbb343a237c847e4d2fbf53'),
                             'asset_generator': h2b('0abd23178d9ff73cf848d8d88\
a7c7e269a464f53017cab0f9f53ed9d64b2849713'),
                             'value_commitment': h2b('094d9a00f1661a2a805a8afe\
c9c188310d4c43353cc319886ee4d9f439389d8f43'),
                             'asset_id': h2b('5ac9f65c0efcc4775e0baec4ec03abdd\
e22473cd3cf33c0419ca290e0751b225'),
                             'value': 9000000}


# The tests
def assert_idle(jade):
    wait(1)  # Short delay to ensure return to idle status
    rslt = jade.ping()
    assert rslt == 0  # idle


def test_mnemonic_import_bad(jade):
    # Check importing invalid mnemonics
    bad_mnemonics = [
        # mnemonic phrase
        TEST_MNEMONIC_PREFIXES_AMBIGUOUS,        # ambiguous prefixes
        # seedsigner
        TEST_MNEMONIC_SEEDSIGNER[:-1],           # bad length (too short)
        TEST_MNEMONIC_SEEDSIGNER + '1234',       # bad length (too long)
        TEST_MNEMONIC_SEEDSIGNER[:-4] + '2048',  # out of range
        TEST_MNEMONIC_SEEDSIGNER[:-4] + '0000',  # invalid checksum word
        TEST_MNEMONIC_SEEDSIGNER_COMPACT[:-1],   # bad length (compact case)
        # bcur-bip39
        TEST_MNEMONIC_BCUR_BIP39_TOO_MANY,       # too many words
        TEST_MNEMONIC_BCUR_BIP39_TOO_FEW,        # too few words
        TEST_MNEMONIC_BCUR_BIP39_LONG_WORD,      # word too long
        TEST_MNEMONIC_BCUR_BIP39_EMPTY_WORD,     # empty word
    ]
    for i, bad_mnemonic in enumerate(bad_mnemonics):
        request = jade.build_request('badmnemonic_' + str(i), 'debug_set_mnemonic',
                                     {'mnemonic': bad_mnemonic})
        reply = jade.make_rpc_call(request)
        assert reply['id'] == request['id']
        assert 'result' not in reply
        assert reply['error']['code'] == JadeError.BAD_PARAMETERS
        message = reply['error']['message']
        expected = ['Failed to expand mnemonic prefixes',
                    'Failed to extract mnemonic prefixes']
        assert any(m in message for m in expected), message


def test_passphrase(jade):
    # Set mnemonic with/without a passphrase, and get root xpub
    xpub0 = _set_wallet(jade, passphrase=None)
    xpub1 = _set_wallet(jade, passphrase='Passphrase1')
    xpub2 = _set_wallet(jade, passphrase='Passphrase2')

    # Check root xpubs are not the same
    # ie. that the passphrase leads to a different wallet
    assert xpub0 != xpub1 and xpub1 != xpub2 and xpub2 != xpub0

    # Check that using the same passphrase does get the same wallet
    xpub0_again = _set_wallet(jade, passphrase=None)
    xpub1_again = _set_wallet(jade, passphrase='Passphrase1')
    xpub2_again = _set_wallet(jade, passphrase='Passphrase2')

    assert xpub0_again == xpub0 and xpub1_again == xpub1 and xpub2_again == xpub2


# Check/print memory stats
def check_mem_stats(jadeapi, startinfo, endinfo, has_psram, has_ble, strict, retry_count=0):

    # NOTE: skip the fragmentation check when we have BLE enabled
    # as there is too much memory allocation outside of our control.
    # Also skip for no-psram (qemu) devices.
    check_frag = has_psram and not has_ble
    is_v2 = startinfo['BOARD_TYPE'] in ['JADE_V2']

    # Memory stats to log/check
    dram_frag_limit = -1
    if check_frag:
        # TODO: Investigate fragmentation in noradio CI runs
        dram_frag_limit = 18500 if is_v2 else 4096
    breaches = []
    for field, limit in [('JADE_FREE_HEAP', 1536),
                         ('JADE_FREE_DRAM', 8192 if has_ble else 1536),
                         ('JADE_LARGEST_DRAM', dram_frag_limit),
                         ('JADE_FREE_SPIRAM', 1024),
                         ('JADE_LARGEST_SPIRAM', 0 if check_frag else -1)]:
        initial = int(startinfo[field])
        final = int(endinfo[field])
        diff = initial - final

        if limit >= 0 and diff > limit:
            logger.warning(f'{field} - {initial} to {final} ({diff}) BREACH')
            breaches.append(field)
        else:
            logger.info(f'{field} - {initial} to {final} ({diff})')

    MAX_MEM_STATS_RETRIES = 3

    if not breaches:
        if retry_count:
            logger.info(f'Memory stats recovered on retry {retry_count} '
                        f'of {MAX_MEM_STATS_RETRIES}')
        return

    logger.error(f'Memory limit breaches: {breaches}')
    if not strict:
        return

    if retry_count < MAX_MEM_STATS_RETRIES:
        logger.info(f'Retrying memory stats check in 5s '
                    f'(retry {retry_count + 1} of {MAX_MEM_STATS_RETRIES})')
        time.sleep(5)
        endinfo = jadeapi.get_version_info()
        assert len(endinfo) == NUM_VALUES_VERINFO, \
            f'Unexpected version info values: {len(endinfo)}'
        return check_mem_stats(jadeapi, startinfo, endinfotest_bad_params, has_psram, has_ble, strict,
                               retry_count=retry_count + 1)

    assert not breaches, \
        f'Memory limit breaches after {MAX_MEM_STATS_RETRIES} retries: {breaches}'


# Helper to verify a signature - handles checking an Anti-Exfil signature
# contains the entropy that was passed in by the host.
def _verify_signature(jadeapi, network, msghash, path,
                      host_entropy, signer_commitment,
                      signature, is_schnorr):
    is_liquid = 'liquid' in network
    # entropy/signer_commitment imply anti-exfil signature
    assert (host_entropy is None) == (signer_commitment is None)

    # Need to get the signer's pubkey
    xpub = jadeapi.get_xpub(network, path)
    hdkey = wally.bip32_key_from_base58(xpub)
    pubkey = wally.bip32_key_get_pub_key(hdkey)

    if is_schnorr:
        # Taproot signature. Tweak the pubkey for a keyspend and verify
        assert signer_commitment == bytes()  # No Anti-Exfil for Schnorr yet
        assert len(signature) == wally.EC_SIGNATURE_LEN
        flags = wally.EC_FLAG_ELEMENTS if is_liquid else 0
        pubkey = wally.ec_public_key_bip341_tweak(pubkey, None, flags)
        wally.ec_sig_verify(pubkey, msghash, wally.EC_FLAG_SCHNORR, signature)
        return

    # If presented a 'recoverable' signature, recover the public key
    # and verify it matches that fetched from the hw above
    if len(signature) == wally.EC_SIGNATURE_RECOVERABLE_LEN:
        recovered_pubkey = wally.ec_sig_to_public_key(msghash, signature)
        assert recovered_pubkey == pubkey
        signature = signature[1:]  # Truncate leading byte for verification

    # ECDSA signature
    assert len(signature) == wally.EC_SIGNATURE_LEN
    if host_entropy:
        # Verify AE signature and that the host-entropy is included
        wally.ae_verify(pubkey, msghash, host_entropy, signer_commitment,
                        wally.EC_FLAG_ECDSA, signature)
    else:
        # Verify EC signature
        wally.ec_sig_verify(pubkey, msghash, wally.EC_FLAG_ECDSA, signature)



def run_api_tests(jadeapi, isble, qemu, authuser=False):

    rslt = jadeapi.clean_reset()
    assert rslt is True

    assert_idle(jadeapi)

    # On connection, a companion app should:
    # a) get the version info and check is compatible, needs update, etc.
    # b) if firmware ok, optionally send in some entropy for the rng
    # c) optionally set the epcoh time (required to use TOTP)
    # d) tell the jade to authenticate the user (eg. pin entry)
    #    - here we use 'set_mnemonic' instead to replace hw authentication
    rslt = jadeapi.get_version_info(nonblocking=True)
    assert len(rslt) == NUM_VALUES_VERINFO
    rslt = jadeapi.get_version_info()
    assert len(rslt) == NUM_VALUES_VERINFO

    noise = os.urandom(64)
    rslt = jadeapi.add_entropy(bytes(noise))
    assert rslt is True

    rslt = jadeapi.set_epoch(int(time.time()))
    assert rslt is True

    if authuser:
        # Full user authentication with jade and pinserver (must be running)
        rslt = jadeapi.auth_user('testnet', int(time.time()))
        assert rslt is True

    # Set mnemonic here instead of (or to override the result of) 'auth_user'
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    # Test logout and log back in before we collect mem stats in case there are
    # 'one off' allocations when we first log in
    assert jadeapi.get_version_info()['JADE_STATE'] == 'READY'
    jadeapi.logout()
    assert jadeapi.get_version_info()['JADE_STATE'] in ['LOCKED', 'UNINIT']
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert jadeapi.get_version_info()['JADE_STATE'] == 'READY'

    assert_idle(jadeapi)

    wait(5)  # Lets idle tasks clean up
    startinfo = jadeapi.get_version_info()
    assert len(startinfo) == NUM_VALUES_VERINFO
    has_psram = startinfo['JADE_FREE_SPIRAM'] > 0
    has_ble = startinfo['JADE_CONFIG'] == 'BLE'

    # restore the mnemonic
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    wait(5)  # Lets idle tasks clean up
    endinfo = jadeapi.get_version_info()
    strict = endinfo['BOARD_TYPE'] != 'JADE_V2C'  # TODO: enable for v2.0c
    check_mem_stats(jadeapi, startinfo, endinfo, has_psram, has_ble, strict=strict)

    rslt = jadeapi.clean_reset()
    assert rslt is True


# Run tests using passed interface
def run_interface_tests(jadeapi,
                        isble,
                        qemu,
                        authuser=False,
                        smoke=True,
                        negative=True):
    assert jadeapi is not None

    rslt = jadeapi.clean_reset()
    assert rslt is True

    # Log out and log back in before we collect mem stats in case there are
    # 'one off' allocations when we first log in
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True
    rslt = jadeapi.logout()
    assert rslt is True

    wait(5)  # Lets idle tasks clean up
    startinfo = jadeapi.get_version_info()
    assert len(startinfo) == NUM_VALUES_VERINFO
    has_psram = startinfo['JADE_FREE_SPIRAM'] > 0
    has_ble = startinfo['JADE_CONFIG'] == 'BLE'
    is_s3 = startinfo['BOARD_TYPE'] in ESP32S3_CHIP_BOARDS

    rslt = jadeapi.get_version_info(nonblocking=True)
    assert len(rslt) == NUM_VALUES_VERINFO
    assert rslt['EFUSEMAC'] == startinfo['EFUSEMAC']
    assert rslt['JADE_CONFIG'] == startinfo['JADE_CONFIG']
    assert rslt['JADE_VERSION'] == startinfo['JADE_VERSION']
    assert rslt['JADE_STATE'] == startinfo['JADE_STATE']

    assert_idle(jadeapi)
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True
    assert_idle(jadeapi)

    # Smoke tests
    if smoke:
        logger.info('Smoke tests')

        # Sanity check selfcheck time on Jade hw (skip for qemu)
        # May need updating if more tests added to selfcheck.c
        # Don't need to run internal tests more than once (so skip for ble)
        if not isble:
            time_ms = jadeapi.run_remote_selfcheck()
            logger.info(f'selfcheck time: {time_ms} ms')
            assert qemu or time_ms < (54000 if is_s3 else 134000)

        # Fix after mnemonic tests removal
        rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
        assert rslt

    rslt = jadeapi.logout()
    assert rslt is True

    wait(5)  # Lets idle tasks clean up
    endinfo = jadeapi.get_version_info()
    strict = endinfo['BOARD_TYPE'] != 'JADE_V2C'  # TODO: enable for v2.0c
    check_mem_stats(jadeapi, startinfo, endinfo, has_psram, has_ble, strict=strict)

    rslt = jadeapi.clean_reset()
    assert rslt is True


# Run all selected tests over a passed JadeAPI instance.
def run_jade_tests(jadeapi, isble):
    logger.info(f'Running selected Jade tests over passed connection, is_ble={isble}')

    if args.json_filter:
        run_api_tests(jadeapi, isble, args.qemu, authuser=args.authuser)
        return

    # Low-level JadeInterface tests
    if not args.skiplow:
        run_interface_tests(jadeapi, isble, args.qemu, authuser=args.authuser)

    # High-level JadeAPI tests
    if not args.skiphigh:
        run_api_tests(jadeapi, isble, args.qemu, authuser=args.authuser)


# This test should be passed 2 different connection details to the same jade hw
# Test that is we auth over one, we can't connect with the other.
def mixed_sources_test(serialport, bleid):
    logger.info('Running mixed sources tests')
    SRTIMEOUT = 3  # Use a short timeout
    SCAN_TIMEOUT = 6

    # Example of a 'sensitve' call
    path, network, expected = GET_XPUB_DATA[0]

    # 1. Authorise over serial, check BLE connection fails
    with JadeAPI.create_serial(serialport, timeout=SRTIMEOUT) as jade_serial:
        jade_serial.set_mnemonic(TEST_MNEMONIC)
        wait(1)

        rslt = jade_serial.get_xpub(network, path)
        assert rslt == expected

        try:
            # With BLE we shouldn't even be able to scan/connect the device
            with JadeAPI.create_ble(serial_number=bleid, scan_timeout=SCAN_TIMEOUT) as jade_ble:
                assert False, 'Expected BLE connection to fail as authorised over serial!'

        except JadeError as err:
            assert err.code == 1 and 'Unable to locate BLE device' in err.message

        rslt = jade_serial.logout()
        assert rslt is True

    # 2. Authorise over BLE, check serial connection can be made, but is limited
    with JadeAPI.create_ble(serial_number=bleid) as jade_ble:
        rslt = jade_ble.set_mnemonic(TEST_MNEMONIC)
        assert rslt

        rslt = jade_ble.get_xpub(network, path)
        assert rslt == expected

        # With serial it can connect but can't make any 'wallet-sensitive' calls
        # expect 'HW_LOCKED' error over un-authenticated connection
        with JadeAPI.create_serial(serialport, timeout=SRTIMEOUT) as jade_serial:
            # Can, for example, get info
            info = jade_serial.get_version_info()
            assert len(info) == NUM_VALUES_VERINFO

            try:
                rslt = jade_serial.get_xpub(network, path)
                assert False, 'Expected exception from mixed sources test'
            except JadeError as err:
                assert err.code == JadeError.HW_LOCKED

            # Can unlock with serial, but that will break BLE connection
            rslt = jade_serial.set_mnemonic(TEST_MNEMONIC)
            assert rslt

            rslt = jade_serial.get_xpub(network, path)
            assert rslt == expected

            # BLE connection should now be broken
            try:
                rslt = jade_ble.get_xpub(network, path)
                assert False, 'Expected exception from mixed sources test'
            except AssertionError as err:
                assert jade_ble.jade.impl.client is None

            rslt = jade_serial.logout()
            assert rslt is True

    # 3. Check BLE re-enabled, and both interfces can be used when user not authenticated
    wait(1)
    with JadeAPI.create_serial(serialport, timeout=SRTIMEOUT) as jade_serial:
        info1 = jade_serial.get_version_info()
        with JadeAPI.create_ble(serial_number=bleid) as jade_ble:
            info2 = jade_ble.get_version_info()
            info1 = jade_serial.get_version_info()

        rslt = jade_serial.clean_reset()
        assert rslt is True


# Run all selected tests over all selected backends (serial/ble)
def run_all_jade_tests(info):
    logger.info('Running Jade tests over selected backend interfaces')

    if args.libjade:
        logger.info("Testing libjade")
        with JadeAPI.create_libjade(timeout=0) as jade:
            run_jade_tests(jade, isble=False)

    # 1. Test over serial connection
    if not args.skipserial:
        logger.info(f'Testing Serial ({args.serialport})')
        with JadeAPI.create_serial(args.serialport,
                                   timeout=args.serialtimeout) as jade:
            run_jade_tests(jade, isble=False)

    # 2. Test over BLE connection
    if not args.skipble:
        if info['JADE_CONFIG'] == 'BLE':
            bleid = info['EFUSEMAC'][6:]
            logger.info(f'Testing BLE ({bleid})')
            with JadeAPI.create_ble(serial_number=bleid) as jade:
                run_jade_tests(jade, isble=True)

            # 3. If testing both interfaces, test cannot connect 'other' when one in use
            if not args.skipserial:
                mixed_sources_test(args.serialport, bleid)
        else:
            msg = 'Skipping BLE tests - not enabled on the hardware'
            logger.warning(msg)


# Connect to Jade by serial or BLE and get the info block
def get_jade_info():
    if args.libjade:
        logger.info("Getting info via libjade")
        with JadeAPI.create_libjade() as jade:
            return jade.get_version_info()

    if not args.skipserial:
        logger.info(f'Getting info via Serial ({args.serialport})')
        with JadeAPI.create_serial(device=args.serialport,
                                   timeout=args.serialtimeout) as jade:
            return jade.get_version_info()

    if not args.skipble:
        bleid = args.bleid
        logger.info(f'Getting info via BLE ({id or "<any>"})')
        with JadeAPI.create_ble(serial_number=bleid) as jade:
            return jade.get_version_info()


def test_ble_connection_fails(info):
    if not args.skipble:
        if info['JADE_CONFIG'] == 'BLE':
            bleid = info['EFUSEMAC'][6:]
            logger.info('Testing BLE connection fails or times-out')
            jade = JadeAPI.create_ble(serial_number=bleid)

            # When timeout elapses, raise interrupt/exception
            def _on_timeout():
                logger.info('test_ble_connection_fails() - connection timeout')
                _thread.interrupt_main()  # raises KeyboardInterrupt exception

            # Try to connect a few times.
            # Assert if connection succeeds at all.
            # (Time-out if connections hangs)
            for _ in range(3):
                # Start 10s timeout clock
                timer = threading.Timer(10, _on_timeout)
                timer.start()

                try:
                    jade.connect()
                    jade.get_version_info()
                    assert False, 'test_ble_connection_fails() connected!'
                except KeyboardInterrupt as e:
                    logger.info(f'BLE connection timed-out: {e}')
                except Exception as e:
                    logger.info(f'BLE connection failed with: {e}')
                finally:
                    timer.cancel()
                    jade.disconnect()
        else:
            msg = 'Skipping BLE tests - not enabled on the hardware'
            logger.warning(msg)


def check_stuck():
    # NOTE: belt'n'braces - serial/ble reads/writes should timeout before this does
    timeout = 90 if args.qemu else 60  # minutes
    time.sleep(60 * timeout)
    logger.error(f'tests got caught running longer than {timeout} minutes, terminating')
    logger.handlers[0].flush()
    os._exit(1)


def start_agent(passkey_file):
    logger.info(f'Starting bt-agent with passkey file: {passkey_file}')
    command = ['/usr/bin/bt-agent', '-c', 'DisplayYesNo', '-p', passkey_file]
    btagent = subprocess.Popen(command,
                               shell=False,
                               stdout=subprocess.DEVNULL)
    logger.info(f'Started bt-agent with process id: {btagent.pid}')
    return btagent


def kill_agent(btagent):
    command = f'kill -HUP {btagent.pid}'
    subprocess.run(command,
                   shell=True,
                   stdout=subprocess.DEVNULL)
    logger.info(f'Killed bt-agent {btagent.pid}')


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    sergrp = parser.add_mutually_exclusive_group()
    sergrp.add_argument('--skipserial',
                        action='store_true',
                        dest='skipserial',
                        help='Skip testing over serial connection',
                        default=False)
    sergrp.add_argument('--serialport',
                        action='store',
                        dest='serialport',
                        help='Serial port or device',
                        default=None)

    blegrp = parser.add_mutually_exclusive_group()
    blegrp.add_argument('--skipble',
                        action='store_true',
                        dest='skipble',
                        help='Skip testing over BLE connection',
                        default=False)
    blegrp.add_argument('--bleid',
                        action='store',
                        dest='bleid',
                        help='BLE device serial number or id',
                        default=None)

    skpgrp = parser.add_mutually_exclusive_group()
    skpgrp.add_argument('--skiplow',
                        action='store_true',
                        dest='skiplow',
                        help='Skip low-level JadeInterface (negative) tests',
                        default=False)
    skpgrp.add_argument('--skiphigh',
                        action='store_true',
                        dest='skiphigh',
                        help='Skip high-level JadeAPI (happy-path) tests',
                        default=False)

    agtgrp = parser.add_mutually_exclusive_group()
    agtgrp.add_argument('--noagent',
                        action='store_true',
                        dest='noagent',
                        help='Do not run the BLE passkey agent',
                        default=False)
    agtgrp.add_argument('--agentkeyfile',
                        action='store',
                        dest='agentkeyfile',
                        help='Use the specified BLE passkey agent key file',
                        default=BLE_TEST_PASSKEYFILE)

    parser.add_argument('--serialtimeout',
                        action='store',
                        dest='serialtimeout',
                        type=int,
                        help='Serial port timeout',
                        default=DEFAULT_SERIAL_TIMEOUT)
    parser.add_argument("--libjade",
                        action="store_true",
                        dest="libjade",
                        help="Run tests with in-process libjade",
                        default=False)
    parser.add_argument('--authuser',
                        action='store_true',
                        dest='authuser',
                        help='Full user authentication with Jade & pinserver',
                        default=False)
    parser.add_argument('--qemu',
                        action='store_true',
                        dest='qemu',
                        help='Skip tests which appear problematic on qemu hw emulator',
                        default=False)
    parser.add_argument("--sample-percent",
                        action="store",
                        dest="sample_percent",
                        type=int,
                        help="Run only a random sample of test cases",
                        default=100)
    parser.add_argument('--json-filter',
                        action='store',
                        dest='json_filter',
                        help='Run only cases matching this glob under ./test_data/',
                        default=None)
    parser.add_argument('--log',
                        action='store',
                        dest='loglevel',
                        help='Jade logging level',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                        default='INFO')

    args = parser.parse_args()
    if args.json_filter:
        args.skiplow = True
        args.skiphigh = True
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug(f'args: {args}')

    if args.sample_percent != 100:
        logger.warning(f'WARNING: Testing reduced test cases ({args.sample_percent}% sample)')
    args.spts = args.serialport and not args.serialport.startswith('/dev/tty/') and not args.qemu

    manage_agents = args.agentkeyfile and not args.skipble and \
        not args.noagent and not args.spts and not args.libjade

    if args.libjade:
        args.skipserial = True
        args.skipble = True
    elif args.skipserial and args.skipble:
        logger.error("Can only skip one of Serial or BLE tests, not both!")
        os.exit(1)

    if args.bleid and not args.skipserial:
        logger.error('Can only supply ble-id when skipping serial tests')
        os.exit(1)

    # Run the thread that forces exit if we're too long running
    if not args.libjade and not args.spts:
        t = threading.Thread(target=check_stuck, daemon=True)
        t.start()

    # If ble, start the agent to supply the required passkey for authentication
    # and encryption - don't bother if not.
    # Note: passkey in the agent passkey file must match the fixed test passkey
    #       in jade source if we want the connection to succeed.
    btagent = None
    if manage_agents:
        btagent = start_agent(args.agentkeyfile)

    # Remove PINs left over from previous test runs
    for f in glob.glob("./*.pin"):
        os.remove(f)

    try:
        info = get_jade_info()
        if info:
            # Tests of low-level interface and negative tests
            run_all_jade_tests(info)

            # FIXME: appears to work (locally) on esp4.1 branch
            # Can only work if only one test running on the box
            # otherwise bt-agents interfere
            # if manage_agents:
            #    # Extra test for bad BLE passkey - should fail or time-out
            #    stop_all_agents()
            #    if btagent:
            #        kill_agent(btagent)
            #    logger.info('Testing BLE fails with incorrect passkey')
            #    btgent = start_agent(BLE_TEST_BADKEYFILE)
            #    test_ble_connection_fails(info)
        else:
            assert False, 'Failed to connect to Jade over serial or BLE'
    finally:
        for f in glob.glob("./*.pin"):
            os.remove(f)
        if btagent:
            kill_agent(btagent)
