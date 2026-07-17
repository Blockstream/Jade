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
NUM_VALUES_VERINFO = 22
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


def test_bad_message(jade):
    bad_requests = [{'method': 'get_version_info'},  # no-id
                    {'id': '2'},               # no method
                    {'id': 123},               # bad id type
                    {'id': '12345'*8},         # id too long
                    {'method': 'x'*40, 'id': '4'}]   # method

    for request in bad_requests:
        msgbytes = cbor.dumps(request)
        jade.write(msgbytes)

        # Expect one reject message for the bad (but well formed) input
        reply = jade.read_response()

        # Returned id should match sent and valid, or '00' if not
        assert 'id' in reply
        if 'id' in request and \
           isinstance(request['id'], str) and \
           len(request['id']) < 32:
            assert reply['id'] == request['id']  # matches
        else:
            assert reply['id'] == '00'           # default error id

        # Assert bad message response
        assert 'result' not in reply
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'].startswith('Invalid RPC Request message')
        assert int(error['data']) == len(msgbytes)
        assert 'result' not in reply


def test_very_bad_message(jade):
    empty = cbor.dumps(b'')
    text = cbor.dumps('This is not a good cbor message')
    truncated = cbor.dumps("{'id': '1', method: 'msgwillbecut'}")[1:]
    goodmsg = jade.build_request('ent', 'add_entropy', {'entropy': 'noise'.encode()})

    for badmsg in [empty, text, truncated]:
        # Send the bad message, and after a pause a good message
        jade.write(badmsg)
        wait(STALE_DATA_TIMEOUT, force=True)
        jade.write_request(goodmsg)

        # We should receive a bag of errors
        # NOTE: we cannot be sure how many messages will be returned exactly,
        # but we do know that Jade should reject a total of 'len(badmsg)' bytes.
        bad_bytes = 0
        while bad_bytes < len(badmsg):
            reply = jade.read_response()

            # Returned id should be '00'
            assert reply['id'] == '00'
            assert 'result' not in reply

            # Assert bad message response
            error = reply['error']
            assert error['code'] == JadeError.INVALID_REQUEST
            assert error['message'].startswith('Invalid RPC Request message')
            bad_bytes += int(error['data'])

        assert bad_bytes == len(badmsg)

        # After the bad bytes have been rejected, we expect to see the reply to the good message
        reply = jade.read_response()
        assert reply['id'] == 'ent'
        assert 'error' not in reply
        assert 'result' in reply
        assert reply['result'] is True


def test_random_bytes(jade):
    # Stream up 1k of random bytes, then a good message after a short pause
    # NOTE: use fixed pseudo-random here, so test run is reproducible
    random.seed(12345678, 2)
    nsent = 0
    for _ in range(8):
        noise = random.getrandbits(128*8).to_bytes(128, 'little')
        jade.write(noise)
        nsent += len(noise)

    wait(STALE_DATA_TIMEOUT, force=True)
    goodmsg = jade.build_request('goodmsg', 'add_entropy', {'entropy': 'somebytes'.encode()})
    jade.write_request(goodmsg)

    # We should receive a bag of errors
    # NOTE: we cannot be sure how many messages will be returned exactly,
    # but we do know that Jade should reject a total of 'nsent' bytes.
    nreceived = 0
    while nreceived < nsent:
        # Expect error - count rejected bytes
        reply = jade.read_response()
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'].startswith('Invalid RPC Request message')
        nreceived += int(error['data'])

    assert nreceived == nsent

    # After the bad bytes have been rejected, we expect to see the reply to the good message
    reply = jade.read_response()
    assert reply['id'] == 'goodmsg'
    assert 'error' not in reply
    assert 'result' in reply
    assert reply['result'] is True


def test_too_much_input(jade, has_psram):
    noise = 'long'.encode()   # 4b
    cacophony = noise * 4096  # 16k

    # NOTE: if the hw has PSRAM it will have a 401k buffer.
    # If not, it will have a 17k buffer.  Want only 1k left.
    # Send the appropriate amount of noise. (400k or 16k)
    if has_psram:
        cacophony = cacophony * 25  # 25x16 is 400k

    # Input buffer would now only have 1k space remaining.
    # Add another 1k to fill the buffer
    cacophony += noise * 256  # 1k
    expected_buffer_size = len(cacophony)

    # Then add another 64b to overflow
    extra = noise * 16  # 64b
    cacophony += extra

    # Format as a cbor message, otherwise it gets rejected early, as soon
    # as the parser decides the bytes it has are not a valid message.
    # See: test_very_bad_message() above.
    big_msg = cbor.dumps({'method': 'toobig', 'id': 'tohandle', 'params': cacophony})
    # Adjust the expected_overflow_len for the cbor overhead
    total_len = len(big_msg)
    expected_overflow_len = total_len - expected_buffer_size

    # Send the message up with 4k writes
    # (otherwise, trying to write too much can hit the timeout)
    remaining = total_len
    while remaining:
        tosend = min(remaining, 4096)
        jade.write(big_msg[total_len - remaining: (total_len - remaining) + tosend])
        remaining -= tosend

    # First we expect to get a response about the buffer-overflow bytes
    # ie. one (initial) reject message with a big number in!
    reply = jade.read_response()
    error = reply['error']
    assert error['code'] == JadeError.INVALID_REQUEST
    assert error['message'].startswith('Invalid RPC Request message')
    assert int(error['data']) == expected_buffer_size

    # After a short pause send a good message
    wait(STALE_DATA_TIMEOUT, force=True)
    goodmsg = jade.build_request('trailer', 'add_entropy', {'entropy': 'random'.encode()})
    jade.write_request(goodmsg)

    # We should then receive a bag of errors
    # NOTE: we cannot be sure how many messages will be returned exactly,
    # but we do know that Jade should reject a total of 'expected_overflow_len' bytes.
    bad_bytes = 0
    while bad_bytes < expected_overflow_len:
        # Expect error - collect bad bytes
        reply = jade.read_response()
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'].startswith('Invalid RPC Request message')
        bad_bytes += int(error['data'])

    assert bad_bytes == expected_overflow_len, f'{bad_bytes} != {expected_overflow_len}'

    # After the bad bytes have been rejected, we expect to see the reply to the good message
    reply = jade.read_response()
    assert reply['id'] == 'trailer'
    assert 'error' not in reply
    assert 'result' in reply
    assert reply['result'] is True


def test_split_message(jade):
    # Simulate transport stream being v.slow
    msg = cbor.dumps({'method': 'get_version_info', 'id': '24680'})
    for msgpart in [msg[:5], msg[5:10], msg[10:]]:
        jade.write(msgpart)
        wait(0.25, force=True)

    reply = jade.read_response()

    # Returned id should match sent
    assert reply['id'] == '24680'
    assert 'error' not in reply
    assert 'result' in reply and len(reply['result']) == NUM_VALUES_VERINFO


def test_concatenated_messages(jade, do_wait):
    # Simulate a 'bad' client sending two messages without waiting for a reply
    msg1 = {'method': 'get_version_info', 'id': '123456'}
    msg2 = {'method': 'get_version_info', 'id': '456789'}
    concat_cbor = cbor.dumps(msg1) + cbor.dumps(msg2)
    # Split the write of the messages in two at a random point
    split_point = random.randint(1, len(concat_cbor) - 1)
    jade.write(concat_cbor[:split_point])
    if do_wait:
        # Force the first write to timeout (become stale)
        wait(STALE_DATA_TIMEOUT, force=True)
    jade.write(concat_cbor[split_point:])

    reply1 = jade.read_response()
    reply2 = jade.read_response()

    # Returned ids should match sent
    for msg, reply in [(msg1, reply1), (msg2, reply2)]:
        assert reply['id'] == msg['id']
        assert 'error' not in reply
        assert 'result' in reply and len(reply['result']) == NUM_VALUES_VERINFO


def test_unknown_method(jade):
    # Includes tests of method prefixes 'get...' and 'sign...'
    for msgid, method in [('unk0', 'dostuff'), ('unk1', 'get'), ('unk2', 'sign'),
                          ('unk3', 'handshake_init')]:
        request = jade.build_request(msgid, method,
                                     {'path': (0, 1, 2, 3, 4),
                                      'message': 'Jade is cool'})
        reply = jade.make_rpc_call(request)

        # Returned id should match sent
        assert reply['id'] == msgid

        # Assert unknown method response
        error = reply['error']
        assert error['code'] == JadeError.UNKNOWN_METHOD
        assert error['message'] == 'Unknown method'
        assert 'result' not in reply


def test_unexpected_method(jade):
    # These messages are only expected as a subsequent message
    # in a multi-message protocol.
    unexpected = [('protocol2', 'pin',
                   {'payload': 'abcdef', 'hmac': '1234'}),
                  ('protocol3', 'ota_data', h2b('abcdef')),
                  ('protocol4', 'ota_complete'),
                  ('protocol5', 'tx_input'),
                  ('protocol6', 'get_signature'),
                  ('protocol7', 'get_extended_data')]

    for rpc_args in unexpected:
        request = jade.build_request(*rpc_args)
        reply = jade.make_rpc_call(request)

        # Assert protocol-error/unexpected-method response
        error = reply['error']
        assert error['code'] == JadeError.PROTOCOL_ERROR
        assert error['message'] == 'Unexpected method'
        assert 'result' not in reply


def _test_good_params(jade, rpc_args):
    request = jade.build_request(*rpc_args)
    reply = jade.make_rpc_call(request)

    # Assert all-good response
    assert reply['id'] == request['id']
    assert 'error' not in reply
    assert 'result' in reply
    return reply['result']


def _test_bad_params(jade, rpc_args, expected_error):
    request = jade.build_request(*rpc_args)
    reply = jade.make_rpc_call(request)

    # Assert bad-parameters response
    assert reply['id'] == request['id']
    assert 'result' not in reply
    assert 'error' in reply
    error = reply['error']
    assert error['code'] == JadeError.BAD_PARAMETERS, f"{error['code']}: {rpc_args}"
    assert 'message' in error
    assert expected_error in error['message'], f"{error['message']} != {expected_error}: {rpc_args}"


def test_bad_params(jade):
    GOODTX = h2b(
             '02000000010f757ae0b5714cb36e017dfffafe5f3ba8c89ddb969a0ae60d99ee\
7b5892a2740000000000ffffffff01203f0f00000000001600145f4fcd4a757c2abf6a0691f59d\
ffae18852bbd7300000000')

    MULTI_COSIGNERS = [
        {
          'fingerprint': h2b('1273da33'),
          'derivation': [44, 2147483648, 2147483648],
          'xpub': 'tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3\
GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG',
          'path': [3, 1]
        },
        {
          'fingerprint': h2b('e3ebcc79'),
          'derivation': [2147483651, 2147483649, 1],
          'xpub': 'tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8\
epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka',
          'path': [1]
        }
    ]
    # Default test user is cosigners[1]
    bad_multi_cosigners1 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners1[1]['fingerprint'] = h2b('abcdef')
    bad_multi_cosigners2 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners2[1]['fingerprint'] = bad_multi_cosigners2[0]['fingerprint']
    bad_multi_cosigners3 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners3[1]['derivation'] = [1, 2, 3, 4]
    bad_multi_cosigners4 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners4[1]['path'] = [2147483648]
    bad_multi_cosigners5 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners5[1]['xpub'] = bad_multi_cosigners2[0]['xpub']
    bad_multi_cosigners6 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners6[0]['xpub'] = bad_multi_cosigners6[0]['xpub'].replace('D', 'E', 1)

    DESCRIPTOR = 'wsh(pkh(@0/<0;1>/*))'
    DESCR_SIGNER = "[e3ebcc79/48'/1'/0'/2']tpubDDvj9CrVJ9kWXSL2kjtA8v53rZvTmL3\
HmWPvgD3hiTnD5KZuMkxSUsgGraZ9vavB5JSA3F9s5E4cXuCte5rvBs5N4DjfxYssQk1L82Bq4FE"
    bad_descr_signer1 = '[abcdef' + DESCR_SIGNER[DESCR_SIGNER.find('/'):]
    bad_descr_signer2 = '[1273da33' + DESCR_SIGNER[DESCR_SIGNER.find('/'):]
    bad_descr_signer3 = '[e3ebcc79/1/2/3/4' + DESCR_SIGNER[DESCR_SIGNER.find(']'):]

    trezor_id_test = list(_get_test_cases('identity_ssh_nist_matches_trezor.json'))
    assert len(trezor_id_test) == 1
    GOOD_ECDH_PUBKEY = trezor_id_test[0]['expected_output']['slip-0017']

    bad_params = [(('badauth1', 'auth_user'), 'Expecting parameters map'),
                  (('badauth2', 'auth_user', {'network': None}), 'extract valid network'),
                  (('badauth3', 'auth_user', {'network': 1234512345}), 'extract valid network'),
                  (('badauth4', 'auth_user', {'network': ''}), 'extract valid network'),
                  (('badauth5', 'auth_user', {'network': 'notanetwork'}), 'extract valid network'),
                  (('badauth6', 'auth_user', {'network': 'testnet', 'epoch': 'notanumber'}),
                   'valid epoch value'),
                  (('badauth7', 'auth_user', {'network': 'testnet', 'epoch': 12345.6789}),
                   'valid epoch value'),

                  (('badpin1', 'update_pinserver'), 'Expecting parameters map'),
                  (('badpin2', 'update_pinserver',
                    {'urlA': ''}), 'invalid first URL'),
                  (('badpin3', 'update_pinserver',
                    {'urlA': '192.168.1.123'}), 'invalid first URL'),
                  (('badpin4', 'update_pinserver',
                    {'urlA': 'ftp://192.168.1.123'}), 'invalid first URL'),
                  (('badpin5', 'update_pinserver',
                    {'urlA': 'http://192.168.1.123', 'urlB': 'testurl.com:8080'}),
                   'Invalid second URL'),
                  (('badpin6', 'update_pinserver',
                    {'urlA': 'http://192.168.1.123', 'urlB': 'madeup://testurl.com:8080'}),
                   'Invalid second URL'),
                  (('badpin7', 'update_pinserver',
                    {'urlB': 'https://192.168.1.124'}), 'set only second URL'),
                  (('badpin8', 'update_pinserver',
                    {'urlA': 'http://192.168.1.123', 'urlB': 'https://192.168.1.124',
                     'reset_details': True}), 'set and reset details'),
                  (('badpin9', 'update_pinserver',
                    {'pubkey': h2b('abc123'), 'reset_details': True}), 'set and reset details'),
                  (('badpin10', 'update_pinserver',
                    {'pubkey': h2b('abcdef')}), 'set pubkey without URL'),
                  (('badpin11', 'update_pinserver',
                    {'urlA': 'http://192.168.1.123', 'urlB': 'https://192.168.1.124',
                     'pubkey': h2b('abcdef1234')}), 'Invalid Oracle pubkey'),
                  (('badpin12', 'update_pinserver',
                    {'certificate': 'testcert', 'reset_certificate': True}),
                   'set and reset certificate'),

                  (('badent1', 'add_entropy'), 'Expecting parameters map'),
                  (('badent2', 'add_entropy', {'entropy': None}), 'valid entropy bytes'),
                  (('badent3', 'add_entropy', {'entropy': 1234512345}), 'valid entropy bytes'),
                  (('badent4', 'add_entropy', {'entropy': b''}), 'valid entropy bytes'),
                  (('badent5', 'add_entropy', {'entropy': 'notbinary'}), 'valid entropy bytes'),

                  (('badepoch1', 'set_epoch'), 'Expecting parameters map'),
                  (('badepoch2', 'set_epoch', {'epoch': None}), 'valid epoch value'),
                  (('badepoch3', 'set_epoch', {'epoch': ''}), 'valid epoch value'),
                  (('badepoch4', 'set_epoch', {'epoch': 'notinteger'}), 'valid epoch value'),
                  (('badepoch5', 'set_epoch', {'epoch': 12345.6789}), 'valid epoch value'),

                  (('badota1', 'ota'), ''),
                  (('badota2', 'ota', {'fwsize': 12345}), 'Bad filesize parameters'),
                  (('badota3', 'ota',
                    {'fwsize': '1234', 'cmpsize': '123'}), 'Bad filesize parameters'),
                  (('badota4', 'ota',
                    {'fwsize': 'X', 'cmpsize': 'Y'}), 'Bad filesize parameters'),
                  (('badota5', 'ota',  # compsize >= fwsize rejected
                    {'fwsize': 1234, 'cmpsize': 1234}), 'Bad filesize parameters'),
                  (('badota6', 'ota',  # hash unexpected size
                    {'fwsize': 1234, 'cmpsize': 1111, 'cmphash': b'123'}), 'extract valid fw hash'),
                  (('badota_delta1', 'ota_delta'), ''),
                  (('badota_delta2', 'ota_delta', {'fwsize': 12345}), 'Bad filesize parameters'),
                  (('badota_delta3', 'ota_delta',
                    {'fwsize': '1234', 'cmpsize': '123'}), 'Bad filesize parameters'),
                  (('badota_delta4', 'ota_delta',
                    {'fwsize': 'X', 'cmpsize': 'Y'}), 'Bad filesize parameters'),
                  (('badota_delta5', 'ota_delta',  # compsize >= fwsize rejected
                    {'fwsize': 1234, 'cmpsize': 1234}), 'Bad filesize parameters'),
                  (('badota_delta6', 'ota_delta',  # hash unexpected size
                      {'fwsize': 1234, 'cmpsize': 1111,
                       'patchsize': 1200, 'cmphash': b'123'}), 'extract valid fw hash'),

                  (('badxpub1', 'get_xpub'), 'Expecting parameters map'),
                  (('badxpub2', 'get_xpub',
                    {'notpath': 'X', 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub3', 'get_xpub',
                    {'path': 'X', 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub4', 'get_xpub',
                    {'path': None, 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub5', 'get_xpub',
                    {'path': '', 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub6', 'get_xpub',
                    {'path': [None], 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub7', 'get_xpub',
                    {'path': ['123', '456'], 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub8', 'get_xpub',
                    {'path': ['X', 'Y', 'Z'], 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub9', 'get_xpub',  # path too long
                    {'path': [0, 1, 2] * 6, 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub10', 'get_xpub',  # path value too large
                    {'path': [0xFFFFFFFF + 1], 'network': 'testnet'}), 'extract valid path'),
                  (('badxpub11', 'get_xpub', {'path': [1, 2, 3]}), 'valid network'),
                  (('badxpub12', 'get_xpub',  # network missing or invalid
                    {'path': [], 'network': 'invalid'}), 'valid network'),
                  (('badxpub13', 'get_xpub',  # network missing or invalid
                    {'path': [1, 2, 3], 'network': 'invalid'}), 'valid network'),

                  (('badgetmulti1', 'get_registered_multisig'), 'Expecting parameters map'),
                  (('badgetmulti2', 'get_registered_multisig',
                    {'multisig_name': 'notsobad', 'as_file': 'not bool'}),
                   'Failed to extract valid as_file parameter'),
                  (('badgetmulti3', 'get_registered_multisig', {'multisig_name': None}),
                   'invalid multisig name'),
                  (('badgetmulti4', 'get_registered_multisig', {'multisig_name': 'space is bad'}),
                   'invalid multisig name'),
                  (('badgetmulti5', 'get_registered_multisig',
                    {'multisig_name': 'excessivelylong1'}), 'invalid multisig name'),
                  (('badgetmulti6', 'get_registered_multisig', {'multisig_name': 'noexist'}),
                   'does not exist for this signer'),

                  (('badmulti1', 'register_multisig'), 'Expecting parameters map'),
                  (('badmulti2', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': None}), 'invalid multisig name'),
                  (('badmulti3', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'space is bad'}),
                   'invalid multisig name'),
                  (('badmulti4', 'register_multisig',
                    {'network': 'testnet',
                     'multisig_name': 'excessivelylong1'}), 'invalid multisig name'),
                  (('badmulti5', 'register_multisig',
                    {'network': 'testnet',
                     'multisig_name': 'test'}), 'extract multisig descriptor'),
                  (('badmulti6', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                     'threshold': 2, 'signers': []}}), 'Invalid script variant'),
                  (('badmulti7', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                     'variant': 'pkh(k)', 'threshold': 2, 'signers': []}}),
                   'Invalid script variant'),
                  (('badmulti8', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'sorted': 'Yes', 'threshold': 2, 'signers': []}}),
                   'Invalid sorted flag value'),
                  (('badmulti9', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'signers': []}}), 'Invalid multisig threshold'),
                  (('badmulti10', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'threshold': 0, 'signers': []}}),
                   'Invalid multisig threshold'),
                  (('badmulti11', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'threshold': 16, 'signers': []}}),
                   'Invalid multisig threshold'),
                  (('badmulti12', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(wsh(multi(k)))', 'threshold': 5,
                      'signers': MULTI_COSIGNERS}}), 'Invalid multisig threshold'),
                  (('badmulti13', 'register_multisig',  # network missing or invalid
                    {'network': 'noexist', 'multisig_name': 'test'}), 'valid network'),
                  (('badmulti15', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(wsh(multi(k)))', 'threshold': 2,
                      'signers': bad_multi_cosigners1}}), 'Failed to extract valid co-signers'),
                  (('badmulti16', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'threshold': 2,
                      'signers': bad_multi_cosigners2}}), 'Failed to validate co-signers'),
                  (('badmulti17', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2,
                      'signers': bad_multi_cosigners3}}), 'Failed to validate co-signers'),
                  (('badmulti18', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2,
                      'signers': bad_multi_cosigners4}}), 'Failed to validate co-signers'),
                  (('badmulti19', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2,
                      'signers': bad_multi_cosigners5}}), 'Failed to validate co-signers'),
                  (('badmulti20', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2,
                      'signers': bad_multi_cosigners6}}), 'Failed to validate co-signers'),
                  (('badmulti21', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(wsh(multi(k)))', 'threshold': 1, 'signers': MULTI_COSIGNERS,
                      'master_blinding_key': 1234}}),
                   'Invalid blinding key'),
                  (('badmulti22', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'threshold': 1, 'signers': MULTI_COSIGNERS,
                      'master_blinding_key': 'abcdef'}}),
                   'Invalid blinding key'),
                  (('badmulti23', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(wsh(multi(k)))', 'threshold': 1, 'signers': MULTI_COSIGNERS,
                      'master_blinding_key': EXPECTED_MASTER_BLINDING_KEY[:-1]}}),
                   'Invalid blinding key'),

                  (('badgetdescr1', 'get_registered_descriptor'), 'Expecting parameters map'),
                  (('badgetdescr2', 'get_registered_descriptor', {'descriptor_name': None}),
                   'invalid descriptor name'),
                  (('badgetdescr3', 'get_registered_descriptor',
                    {'descriptor_name': 'space is bad'}), 'invalid descriptor name'),
                  (('badgetdescr4', 'get_registered_descriptor',
                    {'descriptor_name': 'excessivelylong1'}), 'invalid descriptor name'),
                  (('badgetmulti5', 'get_registered_descriptor', {'descriptor_name': 'noexist'}),
                   'does not exist for this signer'),

                  (('baddescr1', 'register_descriptor'), 'Expecting parameters map'),
                  (('baddescr2', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': None}), 'invalid descriptor name'),
                  (('baddescr3', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'space is bad'}),
                   'invalid descriptor name'),
                  (('baddescr4', 'register_descriptor',
                    {'network': 'testnet',
                     'descriptor_name': 'excessivelylong1'}), 'invalid descriptor name'),
                  (('baddescr5', 'register_descriptor',
                    {'network': 'testnet',
                     'descriptor_name': 'test'}), 'extract valid output descriptor'),
                  (('baddescr5a', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'toolong',
                     'descriptor': 'x' * 512}), 'extract valid output descriptor'),
                  (('baddescr5b', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'lengthok',
                     'descriptor': 'x' * 511, 'datavalues': {'@1': DESCR_SIGNER}}),
                   'Failed to parse descriptor'),
                  (('baddescr6', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test',
                     'descriptor': 'wsh(pk(' + DESCR_SIGNER + '))'}),
                   'Failed to extract valid parameter values'),
                  (('baddescr7', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test', 'descriptor': DESCRIPTOR,
                     'datavalues': 'Wrong type'}), 'Failed to extract valid parameter values'),
                  (('baddescr8', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test', 'descriptor': DESCRIPTOR,
                     'datavalues': []}), 'Failed to extract valid parameter values'),
                  (('baddescr9', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': 12}}), 'Failed to extract valid parameter values'),
                  (('baddescr10', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': 'Not a key'}}), 'Failed to parse descriptor'),
                  (('baddescr11', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@1': DESCR_SIGNER}}), 'Failed to parse descriptor'),
                  (('baddescr12', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test',
                     'descriptor': 'wsh(pkh(@A/<0;1>/*))', 'datavalues': {'@A': DESCR_SIGNER}}),
                   'Failed to parse descriptor'),
                  (('baddescr13', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'isgood', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': bad_descr_signer1}}), 'Failed to parse descriptor'),
                  (('baddescr14', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'isgood', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': bad_descr_signer2}}), 'Failed to validate signers'),
                  (('baddescr15', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'isgood', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': bad_descr_signer3}}), 'Failed to validate signers'),
                  (('baddescr16', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'isgood', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': DESCR_SIGNER, '@1': DESCR_SIGNER}}),
                   'Failed to parse descriptor'),
                  (('baddescr17', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'too_few', 'descriptor': 'test',
                     'datavalues': {}}), 'Failed to extract valid parameter values'),
                  (('baddescr18', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'too_many', 'descriptor': 'test',
                     'datavalues': {"%15d" % i: "x" * 159 for i in range(16)}}),
                   'Failed to extract valid parameter values'),

                  (('badrecvaddr1', 'get_receive_address'), 'Expecting parameters map'),
                  (('badrecvaddr2', 'get_receive_address',
                    {'subaccount': 'X', 'branch': 1, 'pointer': 1,
                     'network': 'testnet'}), 'extract path elements'),
                  (('badrecvaddr3', 'get_receive_address',
                    {'subaccount': 1, 'branch': 'X', 'pointer': 1,
                     'network': 'testnet'}), 'extract path elements'),
                  (('badrecvaddr4', 'get_receive_address',
                    {'subaccount': 1, 'branch': 1, 'pointer': 'X',
                     'network': 'testnet'}), 'extract path elements'),
                  (('badrecvaddr5', 'get_receive_address',
                    {'subaccount': 1, 'branch': 1, 'pointer': 1,
                     'network': 'testnet', 'csv_blocks': 0,
                     'recovery_xpub': 'notanxpub'}), 'generate valid green address script'),
                  (('badrecvaddr6', 'get_receive_address',  # 2of3-csv not supported
                    {'subaccount': 1, 'branch': 1, 'pointer': 1,
                     'network': 'testnet', 'csv_blocks': 65536,
                     'recovery_xpub': 'tpubD8G8MPGsm1E4RsRMfDrmAU5h68cY93p9o8J\
7WmueUfCqSKUvLdRRWqRYxaaDkAXJo9WsiFTYtqQ7YeJc3rMsD7sttjdHKocbvwum7MQwxLy'}),
                   'generate valid green address script'),
                  (('badrecvaddr7', 'get_receive_address',
                    {'subaccount': 0, 'branch': 0, 'pointer': 0,
                     'network': 'testnet'}), 'generate valid green address script'),
                  (('badrecvaddr8', 'get_receive_address',
                    {'subaccount': 0, 'branch': 2, 'pointer': 0,
                     'network': 'testnet'}), 'generate valid green address script'),
                  (('badrecvaddr9', 'get_receive_address',
                    {'subaccount': 0, 'branch': 0, 'pointer': 1000000,
                     'network': 'testnet'}), 'generate valid green address script'),
                  (('badrecvaddr10', 'get_receive_address',
                    {'subaccount': 1, 'branch': 1, 'pointer': 1,
                     'network': 'invalid'}), 'extract valid network'),
                  (('badrecvaddr11', 'get_receive_address',
                    {'path': [1, 2, 3], 'network': 'testnet'}), 'extract path elements'),
                  (('badrecvaddr12', 'get_receive_address',
                    {'subaccount': 1, 'branch': 1, 'pointer': 1, 'variant': 'pkh(k)',
                     'network': 'testnet'}), 'extract valid path'),
                  (('badrecvaddr13', 'get_receive_address',
                    {'path': [0xFFFFFFFF + 1], 'variant': 'pkh(k)',
                     'network': 'testnet'}), 'extract valid path'),
                  (('badrecvaddr14', 'get_receive_address',
                    {'path': [1, 2, 3], 'variant': 'p2pkh',
                     'network': 'testnet'}), 'Invalid script variant parameter'),
                  (('badrecvaddr15', 'get_receive_address',
                    {'paths': [[1], [2, 3]], 'multisig_name': 'does not exist',
                     'network': 'testnet'}), 'Cannot find named multisig wallet'),
                  (('badrecvaddr16', 'get_receive_address',
                    {'branch': 0, 'pointer': 1, 'descriptor_name': 'does not exist',
                     'network': 'testnet'}), 'Cannot find named descriptor wallet'),
                  (('badrecvaddr17', 'get_receive_address',
                    {'path': [1, 2, 3], 'variant': 'pkh(k)', 'confidential': True,
                     'network': 'mainnet'}), 'Confidential addresses only apply to liquid'),

                  (('badbip85ent1', 'get_bip85_bip39_entropy'), 'Expecting parameters map'),
                  (('badbip85ent2', 'get_bip85_bip39_entropy',
                    {'num_words': None}), 'valid number of words'),
                  (('badbip85ent3', 'get_bip85_bip39_entropy',
                    {'num_words': 'bad'}), 'valid number of words'),
                  (('badbip85ent4', 'get_bip85_bip39_entropy',
                    {'num_words': 18}), 'valid number of words'),
                  (('badbip85ent5', 'get_bip85_bip39_entropy',
                    {'num_words': 12}), 'fetch valid index'),
                  (('badbip85ent6', 'get_bip85_bip39_entropy',
                    {'num_words': 12, 'index': None}), 'fetch valid index'),
                  (('badbip85ent7', 'get_bip85_bip39_entropy',
                    {'num_words': 12, 'index': 'bad'}), 'fetch valid index'),
                  (('badbip85ent8', 'get_bip85_bip39_entropy',
                    {'num_words': 24, 'index': 0}), 'fetch valid pubkey'),
                  (('badbip85ent9', 'get_bip85_bip39_entropy',
                    {'num_words': 24, 'index': 0, 'pubkey': 'vbad'}), 'fetch valid pubkey'),
                  (('badbip85ent10', 'get_bip85_bip39_entropy',
                    {'num_words': 24, 'index': 0, 'pubkey': GOOD_ECDH_PUBKEY[:-1]}),
                   'fetch valid pubkey'),
                  (('badbip85ent11', 'get_bip85_bip39_entropy',
                    {'num_words': 24, 'index': 0, 'pubkey': b''}),
                   'fetch valid pubkey'),

                  (('badbip85pk1', 'get_bip85_pubkey'), 'Expecting parameters map'),
                  (('badbip85pk2', 'get_bip85_pubkey',
                    {'key_type': None}), 'extract valid key_type'),
                  (('badbip85pk3', 'get_bip85_pubkey',
                    {'key_type': 'bad'}), 'extract valid key_type'),
                  (('badbip85pk4', 'get_bip85_pubkey',
                    {'key_type': 'RSAx'}), 'extract valid key_type'),
                  (('badbip85pk5', 'get_bip85_pubkey',
                    {'key_type': 'RSA'}), 'fetch valid key length'),
                  (('badbip85pk6', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': None}), 'fetch valid key length'),
                  (('badbip85pk7', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': 'bad'}), 'fetch valid key length'),
                  (('badbip85pk8', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': 3096}), 'fetch valid key length'),
                  (('badbip85pk9', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': 8192}), 'fetch valid key length'),
                  (('badbip85pk10', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': 2048}), 'fetch valid index'),
                  (('badbip85pk11', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': 3072, 'index': None}),
                   'fetch valid index'),
                  (('badbip85pk12', 'get_bip85_pubkey',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 'bad'}),
                   'fetch valid index'),

                  (('badbip85sign1', 'sign_bip85_digests'), 'Expecting parameters map'),
                  (('badbip85sign2', 'sign_bip85_digests',
                    {'key_type': None}), 'extract valid key_type'),
                  (('badbip85sign3', 'sign_bip85_digests',
                    {'key_type': 'bad'}), 'extract valid key_type'),
                  (('badbip85sign4', 'sign_bip85_digests',
                    {'key_type': 'RSAx'}), 'extract valid key_type'),
                  (('badbip85sign5', 'sign_bip85_digests',
                    {'key_type': 'RSA'}), 'fetch valid key length'),
                  (('badbip85sign6', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': None}), 'fetch valid key length'),
                  (('badbip85sign7', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 'bad'}), 'fetch valid key length'),
                  (('badbip85sign8', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 3096}), 'fetch valid key length'),
                  (('badbip85sign8', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 8192}), 'fetch valid key length'),
                  (('badbip85sign10', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 2048}), 'fetch valid index'),
                  (('badbip85sign11', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 3072, 'index': None}),
                   'fetch valid index'),
                  (('badbip85sign12', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 'bad'}),
                   'fetch valid index'),
                  (('badbip85sign13', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 0}),
                   'extract digests from parameters'),
                  (('badbip85sign14', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 0, 'digests': None}),
                   'extract digests from parameters'),
                  (('badbip85sign15', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 0, 'digests': 'not array'}),
                   'extract digests from parameters'),
                  (('badbip85sign16', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 0, 'digests': ['not binary']}),
                   'extract digests from parameters'),
                  (('badbip85sign17', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 0, 'digests': [h2b('ababab')]}),
                   'extract digests from parameters'),
                  (('badbip85sign18', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 1024, 'index': 0,
                     'digests': [h2b('ab') * 32] * 9}),
                   'Unsupported number of digests'),
                  (('badbip85sign19', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 1024, 'index': 0,
                     'digests': [h2b('ab') * 32] * 9}),
                   'Unsupported number of digests'),
                  (('badbip85sign20', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 3072, 'index': 0,
                     'digests': [h2b('ab') * 32] * 7}),
                   'Unsupported number of digests'),
                  (('badbip85sign21', 'sign_bip85_digests',
                    {'key_type': 'RSA', 'key_bits': 4096, 'index': 0,
                     'digests': [h2b('ab') * 32] * 5}),
                   'Unsupported number of digests'),

                  (('badidpk1', 'get_identity_pubkey'), 'Expecting parameters map'),
                  (('badidpk2', 'get_identity_pubkey', {'curve': 'nist256p1'}),
                   'extract valid identity'),
                  (('badidpk3', 'get_identity_pubkey', {'identity': 'xxx', 'curve': 'nist256p1'}),
                   'extract valid identity'),
                  (('badidpk4', 'get_identity_pubkey',
                    {'identity': 'ssh://', 'curve': 'nist256p1'}),
                   'extract valid identity'),
                  (('badidpk5', 'get_identity_pubkey',
                    {'identity': 'ftp://some.xyz.com', 'curve': 'nist256p1', 'index': 7}),
                   'extract valid identity'),
                  (('badidpk6', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'index': 0}),
                   'extract valid curve name'),
                  (('badidpk7', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': None, 'index': 1}),
                   'extract valid curve name'),
                  (('badidpk8', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 256, 'index': 17}),
                   'extract valid curve name'),
                  (('badidpk9', 'get_identity_pubkey',  # unsupported curve
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'ed25519', 'index': 0}),
                   'extract valid curve name'),
                  (('badidpk10', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1'}),
                   'extract valid key type'),
                  (('badidpk11', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1', 'type': None}),
                   'extract valid key type'),
                  (('badidpk12', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1', 'type': 13}),
                   'extract valid key type'),
                  (('badidpk13', 'get_identity_pubkey',  # unsupported key type
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'type': 'slip-0014'}),
                   'extract valid key type'),
                  (('badidpk14', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'type': 'slip-0013', 'index': 'bad'}),
                   'extract valid index'),
                  (('badidpk15', 'get_identity_pubkey',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'type': 'slip-0017', 'index': 0xFFFFFFFF + 1}),
                   'extract valid index'),

                  (('badidshared1', 'get_identity_shared_key'), 'Expecting parameters map'),
                  (('badidshared2', 'get_identity_shared_key',
                    {'curve': 'nist256p1', 'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid identity'),
                  (('badidshared3', 'get_identity_shared_key',
                    {'identity': 'xxxxxxx', 'curve': 'nist256p1',
                     'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid identity'),
                  (('badidshared4', 'get_identity_shared_key',
                    {'identity': 'ssh://', 'curve': 'nist256p1',
                     'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid identity'),
                  (('badidshared5', 'get_identity_shared_key',
                    {'identity': 'ftp://some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid identity'),
                  (('badidshared6', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid curve name'),
                  (('badidshared7', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': None,
                     'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid curve name'),
                  (('badidshared8', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 3,
                     'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid curve name'),
                  (('badidshared9', 'get_identity_shared_key',  # unsupported curve
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'ed25519',
                     'their_pubkey': GOOD_ECDH_PUBKEY}),
                   'extract valid curve name'),
                  (('badidshared10', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': None,
                     'index': 2}),
                   'extract valid pubkey'),
                  (('badidshared11', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': 'not-bytes',
                     'index': 0}), 'extract valid pubkey'),
                  (('badidshared12', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': 12345, 'index': 0}),
                   'extract valid pubkey'),
                  (('badidshared13', 'get_identity_shared_key',  # bad pubkey length
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': GOOD_ECDH_PUBKEY[:-1],
                     'index': 0}), 'extract valid pubkey'),
                  (('badidshared14', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': GOOD_ECDH_PUBKEY,
                     'index': 'bad'}), 'extract valid index'),
                  (('badidshared15', 'get_identity_shared_key',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'their_pubkey': GOOD_ECDH_PUBKEY,
                     'index': 0xFFFFFFFF + 1}), 'extract valid index'),

                  (('badsignid1', 'sign_identity'), 'Expecting parameters map'),
                  (('badsignid2', 'sign_identity',
                    {'curve': 'nist256p1', 'challenge': b'abcdef'}), 'extract valid identity'),
                  (('badsignid3', 'sign_identity',
                    {'identity': 'xxxxxxx', 'curve': 'nist256p1', 'challenge': b'abcdef'}),
                   'extract valid identity'),
                  (('badsignid4', 'sign_identity',
                    {'identity': 'ssh://', 'curve': 'nist256p1', 'challenge': b'abcdef'}),
                   'extract valid identity'),
                  (('badsignid5', 'sign_identity',
                    {'identity': 'ftp://some.xyz.com', 'challenge': b'abcdef'}),
                   'extract valid identity'),
                  (('badsignid6', 'sign_identity', {'identity': 'ftp://some.xyz.com',
                    'curve': 'nist256p1'}),
                   'extract valid identity'),
                  (('badsignid7', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'challenge': b'abcdef', 'index': 12}),
                   'extract valid curve name'),
                  (('badsignid8', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': None,
                     'challenge': b'abcdef', 'index': 12}),
                   'extract valid curve name'),
                  (('badsignid9', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 12,
                     'challenge': b'abcdef', 'index': 12}),
                   'extract valid curve name'),
                  (('badsignid10', 'sign_identity',  # unsupported curve
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'ed25519',
                     'challenge': b'abcdef', 'index': 12}),
                   'extract valid curve name'),
                  (('badsignid11', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'challenge': None, 'index': 12}),
                   'extract valid challenge'),
                  (('badsignid12', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'challenge': 'not-bytes', 'index': 0}),
                   'extract valid challenge'),
                  (('badsignid13', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'challenge': 12345, 'index': 0}),
                   'extract valid challenge'),
                  (('badsignid14', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'challenge': b'12345', 'index': 'bad'}),
                   'extract valid index'),
                  (('badsignid15', 'sign_identity',
                    {'identity': 'ssh://user@some.xyz.com', 'curve': 'nist256p1',
                     'challenge': b'12345', 'index': 0xFFFFFFFF + 1}),
                   'extract valid index'),

                  # Note: for signing messages the root key (empty bip32 path
                  # array) is not allowed and should return bad-param.
                  (('badsignmsg1', 'sign_message'), 'Expecting parameters map'),
                  (('badsignmsg2', 'sign_message', {'path': [0]}), 'extract message'),
                  (('badsignmsg3', 'sign_message', {'message': 'XYZ'}), 'extract valid path'),
                  (('badsignmsg4', 'sign_message',
                    {'message': 12345, 'path': [0]}), 'extract message'),
                  (('badsignmsg5', 'sign_message',
                    {'message': '', 'path': [0]}), 'extract message'),
                  (('badsignmsg6', 'sign_message',
                    {'message': 'XYZ', 'path': ''}), 'extract valid path'),
                  (('badsignmsg7', 'sign_message',
                    {'message': 'XYZ', 'path': 'X'}), 'extract valid path'),
                  (('badsignmsg8', 'sign_message',
                    {'message': 'XYZ', 'path': []}), 'extract valid path'),  # Disallowed for sign
                  (('badsignmsg9', 'sign_message',
                    {'message': 'XYZ', 'path': None}), 'extract valid path'),
                  (('badsignmsg10', 'sign_message',
                    {'message': 'XYZ', 'path': [None]}), 'extract valid path'),
                  (('badsignmsg11', 'sign_message',
                    {'message': 'XYZ', 'path': ['123', '456', '789']}), 'extract valid path'),
                  (('badsignmsg12', 'sign_message',
                    {'message': 'XYZ', 'path': ['X', 'Y', 'Z']}), 'extract valid path'),
                  (('badsignmsg13', 'sign_message',  # path too long
                    {'message': 'XYZ', 'path': [0, 1, 2] * 6}), 'extract valid path'),
                  (('badsignmsg14', 'sign_message',  # path value too large
                    {'message': 'XYZ', 'path': [0xFFFFFFFF + 1]}), 'extract valid path'),

                  (('badsignpsbt1', 'sign_psbt'), 'Expecting parameters map'),
                  (('badsignpsbt2', 'sign_psbt', {'psbt': None}), 'extract valid network'),
                  (('badsignpsbt3', 'sign_psbt', {'network': 'testnet', 'psbt': None}),
                   'extract psbt bytes'),
                  (('badsignpsbt4', 'sign_psbt', {'network': 'testnet', 'psbt': 'bad type'}),
                   'extract psbt bytes'),
                  (('badsignpsbt5', 'sign_psbt', {'network': 'mainnet', 'psbt': bytes(256)}),
                   'extract psbt from passed bytes'),

                  (('badsigntx1', 'sign_tx'), 'Expecting parameters map'),
                  (('badsigntx2', 'sign_tx',
                    {'network': 'testnet', 'txn': GOODTX}), 'valid number of inputs'),
                  (('badsigntx3', 'sign_tx',
                    {'txn': GOODTX, 'num_inputs': 1}), 'extract valid network'),
                  (('badsigntx4', 'sign_tx',
                    {'network': 'testnet', 'num_inputs': 1}), 'extract tx'),
                  (('badsigntx4a', 'sign_tx',
                    {'network': 'testnet', 'txn': None, 'num_inputs': 1}), 'extract tx'),
                  (('badsigntx5', 'sign_tx',
                    {'network': 'testnet', 'txn': b'', 'num_inputs': 1}), 'extract tx'),
                  (('badsigntx6', 'sign_tx',
                    {'network': 'testnet', 'txn': 'notbin', 'num_inputs': 1}), 'extract tx'),
                  (('badsigntx7', 'sign_tx',  # Wrong number of inputs
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 2}),
                   'Unexpected number of inputs'),
                  (('badsigntx8', 'sign_tx',  # Wrong number of inputs
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 0}),
                   'valid number of inputs'),
                  (('badsigntx9', 'sign_tx',  # Wrong type
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 'X'}),
                   'valid number of inputs'),
                  (('badsigntx10', 'sign_tx',  # Wrong type
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': None}),
                   'valid number of inputs'),
                  (('badsigntx11', 'sign_tx',  # Bad change outputs
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': []}), 'Unexpected number of output entries'),
                  (('badsigntx12', 'sign_tx',  # invalid network
                    {'network': 'made-up', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'path': [1, 2, 3]}, {}]}), 'extract valid network'),
                  (('badsigntx13', 'sign_tx',  # wrong network type for call
                    {'network': 'localtest-liquid', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'path': [1, 2, 3]}, {}]}), 'not appropriate for liquid'),
                  (('badsigntx14', 'sign_tx',  # missing multisig name
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'multisig_name': '',
                                 'paths': [[1, 2, 3]]}]}), 'Invalid multisig name'),
                  (('badsigntx15', 'sign_tx',  # bad multisig name
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'multisig_name': 'bad', 'is_change': True,
                                 'paths': [[1, 2, 3]]}]}),
                   'Cannot find named multisig wallet'),
                  (('badsigntx16', 'sign_tx',  # missing descriptor name
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'descriptor_name': '',
                                 'branch': 1, 'pointer': 13}]}), 'Invalid descriptor name'),
                  (('badsigntx17', 'sign_tx',  # bad descriptor name
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'descriptor_name': 'bad', 'is_change': True,
                                 'branch': 1, 'pointer': 13}]}),
                   'Cannot find named descriptor wallet'),
                  (('badsigntx19', 'sign_tx',  # missing change path
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'is_change': False, 'not_path': [1, 2, 3]}]}),
                   'extract valid receive path'),
                  (('badsigntx20', 'sign_tx',  # wrong number of outputs
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [None, None]}), 'Unexpected number of output entries')]

    if not LIQUID_DESCRIPTORS:
        bad_params.extend([
            (('baddescr19', 'register_descriptor',
              {'network': 'liquid', 'descriptor_name': 'isgood', 'descriptor': DESCRIPTOR,
               'datavalues': {'@0': DESCR_SIGNER}}), 'not supported on liquid'),
            (('badrecvaddr18', 'get_receive_address',
              {'branch': 0, 'pointer': 1, 'descriptor_name': 'looksvalid',
               'network': 'liquid'}), 'not supported on liquid'),
        ])

    # Test all the simple cases
    for badmsg, errormsg in bad_params:
        if (args.libjade or args.spts) and badmsg[1] in ['ota', 'ota_delta']:
            continue  # Skip ota testing for libjade
        _test_bad_params(jade, badmsg, errormsg)

    bad_tx_inputs = [(('badinput0', 'tx_input'), 'Expecting parameters map'),
                     (('badinput1', 'tx_input',
                       {'is_witness': True, 'satoshi': 120, 'path': []}), 'extract valid path'),
                     (('badinput2', 'tx_input',  # path too long
                       {'is_witness': True, 'satoshi': 120, 'path': [0, 1, 2] * 6}),
                      'extract valid path'),
                     (('badinput2a', 'tx_input',  # path value too large
                       {'is_witness': True, 'satoshi': 120, 'path': [0xFFFFFFFF + 1] * 6}),
                      'extract valid path'),
                     (('badinput3', 'tx_input',
                       {'is_witness': True, 'path': [0],
                        'script': h2b('ABCDEF')}), 'extract satoshi'),
                     (('badinput4', 'tx_input',
                       {'is_witness': True, 'path': [0],
                        'satoshi': '120', 'script': h2b('ABCDEF')}), 'extract satoshi'),
                     (('badinput5', 'tx_input',
                       {'is_witness': True, 'path': [0], 'satoshi': 12}), 'extract script'),
                     (('badinput6', 'tx_input',
                       {'is_witness': True, 'path': [0],
                        'satoshi': 12, 'script': None}), 'extract script'),
                     (('badinput7', 'tx_input',
                       {'is_witness': True, 'path': [0],
                        'satoshi': 12, 'script': 'notbin'}), 'extract script'),
                     (('badinput8', 'tx_input',
                       {'is_witness': False, 'path': [0],
                        'satoshi': 9, 'script': h2b('AB')}), 'extract input_tx'),
                     (('badinput9', 'tx_input',
                       {'is_witness': False, 'input_tx': None}), 'extract input_tx'),
                     (('badinput10', 'tx_input',
                       {'is_witness': False, 'input_tx': 'notbin'}), 'extract input_tx'),
                     (('badinput11', 'tx_input',
                       {'is_witness': True, 'path': [0], 'satoshi': 12345,
                        'script': TEST_SCRIPT, 'sighash': 'SIGHASH_ALL'}), 'fetch valid sighash'),
                     (('badinput12', 'tx_input',
                       {'is_witness': True, 'path': [0], 'satoshi': 12345,
                        'script': TEST_SCRIPT, 'sighash': h2b('02')}), 'fetch valid sighash'),
                     (('badinput13', 'tx_input',
                       {'is_witness': True, 'path': [0], 'satoshi': 12345,
                        'script': TEST_SCRIPT, 'sighash': 300}), 'fetch valid sighash'),
                     (('badinput14', 'tx_input',
                       {'is_witness': True, 'path': [0], 'satoshi': 12345,
                        'script': TEST_SCRIPT, 'sighash': 0}), 'Unsupported sighash value'),
                     (('badinput15', 'tx_input',
                       {'is_witness': True, 'path': [0], 'satoshi': 12345,
                        'script': TEST_SCRIPT, 'sighash': 2}), 'Unsupported sighash value')]

    # Test all the bad tx inputs
    for badinput, errormsg in bad_tx_inputs:
        # Initiate a good sign-tx
        result = _test_good_params(jade, ('signTx', 'sign_tx',
                                          {'network': 'localtest',
                                           'txn': GOODTX,
                                           'num_inputs': 1}))
        assert result is True

        # test a bad input
        _test_bad_params(jade, badinput, errormsg)


def test_bad_params_liquid(jade, has_psram, has_ble):

    GOODTX = h2b(
            '0200000000012413047d152348db4342763a0eece0d99e6e2983b3b46eda07ede\
58d28f201ad0100000000ffffffff020abd23178d9ff73cf848d8d88a7c7e269a464f53017cab0\
f9f53ed9d64b2849713094d9a00f1661a2a805a8afec9c188310d4c43353cc319886ee4d9f4393\
89d8f43033fc2cd1c4ce77e4339984f786dba6591bd862cf397e8cb6a99e457e162cad68617a91\
42e0ef2990318d8c9f7cee627650ba2a84fdda449870125b251070e29ca19043cf33ccd7324e2d\
dab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000f4240000000000000')

    GOOD_COMMITMENT = EXPECTED_LIQ_COMMITMENT_2.copy()
    GOOD_COMMITMENT['blinding_key'] = EXPECTED_BLINDING_KEY
    GOOD_COMMITMENTS = [GOOD_COMMITMENT, {}]  # add a null for the unblind output

    BADVAL32 = EXPECTED_LIQ_COMMITMENT_1['abf']
    BADVAL33 = EXPECTED_LIQ_COMMITMENT_1['value_commitment']

    # Correct lengths, prefixes, etc.
    BAD_ASSET_PROOF = h2b('0100017454d5579ec0def281d4712c832e98af69208af4146ba\
691841d6605088e16c55cb5bffdbad36202475d94dea902fbcfa8c428ab7b3901e92df8b201ac865da3')
    BAD_VALUE_PROOF = h2b('200000000000047f47eb9b2f9267f23f7f64c6f93ab7cb7311b\
305abe97f4ac7877e981ffc7d4f662052de1efc379c28cf17f887e92208e70739e1e7abd095227587a895589e725de8')

    GOOD_ASSET = {
        'asset_id': '38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5',
        'contract': {
            'entity': {
                'domain': 'liquidtestnet.com'
            },
            'issuer_pubkey': '035d0f7b0207d9cc68870abfef621692bce082084ed3ca0c1ae432dd12d889be01',
            'name': 'Testnet Asset',
            'precision': 3,
            'ticker': 'TEST',
            'version': 0
        },
        'issuance_prevout': {
            'txid': '0e19e938c74378ae83b549213a12be88ede6e32e1407bfdf50c4ec3f927408ec',
            'vout': 0
        }
    }

    BAD_ASSET1 = GOOD_ASSET.copy()
    del BAD_ASSET1['contract']

    BAD_ASSET2 = GOOD_ASSET.copy()
    del BAD_ASSET2['contract']['entity']

    BAD_ASSET3 = GOOD_ASSET.copy()
    del BAD_ASSET3['issuance_prevout']

    BAD_ASSET3 = GOOD_ASSET.copy()
    del BAD_ASSET3['issuance_prevout']['txid']

    BAD_ASSET4 = GOOD_ASSET.copy()
    del BAD_ASSET4['asset_id']

    BAD_ASSET5 = GOOD_ASSET.copy()
    BAD_ASSET5['asset_id'] = BADVAL32

    def _commitsMinus(key):
        commits = GOOD_COMMITMENT.copy()
        del commits[key]
        return commits

    def _commitsUpdate(key, val):
        commits = GOOD_COMMITMENT.copy()
        commits[key] = val
        return commits

    def _commitsAssetBlindProof(val):
        commits = _commitsMinus('abf')
        commits['asset_blind_proof'] = val
        return commits

    def _commitsValueBlindProof(val):
        commits = _commitsMinus('vbf')
        commits['value_blind_proof'] = val
        return commits

    bad_params = [(('badblindkey1', 'get_blinding_key'), 'Expecting parameters map'),
                  (('badblindkey2', 'get_blinding_key', {'script': None}), 'extract script'),
                  (('badblindkey3', 'get_blinding_key', {'script': 123}), 'extract script'),
                  (('badblindkey4', 'get_blinding_key', {'script': 'notbin'}), 'extract script'),
                  (('badblindkey5', 'get_blinding_key', {'script': b''}), 'extract script'),

                  (('badnonce1', 'get_shared_nonce'), 'Expecting parameters map'),
                  (('badnonce2', 'get_shared_nonce',
                    {'script': TEST_SCRIPT}), 'extract their_pubkey'),
                  (('badnonce3', 'get_shared_nonce',
                    {'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce4', 'get_shared_nonce',
                    {'script': 123, 'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce5', 'get_shared_nonce',
                    {'script': 'notbin', 'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce5a', 'get_shared_nonce',
                    {'script': b'', 'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce6', 'get_shared_nonce',
                    {'script': TEST_SCRIPT, 'their_pubkey': 123}), 'extract their_pubkey'),
                  (('badnonce7', 'get_shared_nonce',
                    {'script': TEST_SCRIPT, 'their_pubkey': 'notbin'}), 'extract their_pubkey'),
                  (('badnonce8', 'get_shared_nonce',  # short pubkey
                    {'script': TEST_SCRIPT, 'their_pubkey': h2b('ab')}), 'extract their_pubkey'),
                  (('badnonce8a', 'get_shared_nonce',  # short pubkey
                    {'script': TEST_SCRIPT, 'their_pubkey': b''}), 'extract their_pubkey'),
                  (('badnonce9', 'get_shared_nonce',  # bad 'include_pubkey'
                    {'script': TEST_SCRIPT, 'their_pubkey': TEST_THEIR_PK,
                     'include_pubkey': 'True'}), 'extract valid pubkey flag'),

                  (('badblindfac1', 'get_blinding_factor'), 'Expecting parameters map'),
                  (('badblindfac2', 'get_blinding_factor',
                    {'output_index': 0, 'type': 'ASSET'}), 'extract hash_prevouts'),
                  (('badblindfac3', 'get_blinding_factor',
                    {'hash_prevouts': 123, 'output_index': 0,
                     'type': 'ASSET'}), 'extract hash_prevouts'),
                  (('badblindfac3a', 'get_blinding_factor',
                    {'hash_prevouts': b'', 'output_index': 0,
                     'type': 'ASSET'}), 'extract hash_prevouts'),
                  (('badblindfac4', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'type': 'ASSET',
                     'output_index': None}), 'extract output index'),
                  (('badblindfac5', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'type': 'ASSET',
                     'output_index': '3'}), 'extract output index'),
                  (('badblindfac5a', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'type': 'ASSET',
                     'output_index': 98765432123456789}), 'extract output index'),
                  (('badblindfac6', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'type': 'ASSET',
                     'output_index': 'notinteger'}), 'extract output index'),
                  (('badblindfac7', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0}),
                   'extract blinding factor type'),
                  (('badblindfac8', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'type': 123}), 'extract blinding factor type'),
                  (('badblindfac9', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'type': 'BAD'}), 'Invalid blinding factor type'),
                  (('badblindfac10', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'type': 'ASSETXYZ'}), 'Invalid blinding factor type'),
                  (('badblindfac11', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'type': 'VALUEISMUCHTOOLONG'}), 'extract blinding factor type'),

                  (('badcommit1', 'get_commitments'), 'Expecting parameters map'),
                  (('badcommit2', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'value': 123}), 'extract asset_id'),
                  (('badcommit3', 'get_commitments',
                    {'asset_id': None, 'hash_prevouts': TEST_HASH_PREVOUTS,
                     'output_index': 0, 'value': 123}), 'extract asset_id'),
                  (('badcommit4', 'get_commitments',
                    {'asset_id': 123, 'hash_prevouts': TEST_HASH_PREVOUTS,
                     'output_index': 0, 'value': 123}), 'extract asset_id'),
                  (('badcommit5', 'get_commitments',
                    {'asset_id': 'notbin', 'hash_prevouts': TEST_HASH_PREVOUTS,
                     'output_index': 0, 'value': 123}), 'extract asset_id'),
                  (('badcommit6', 'get_commitments',
                    {'asset_id': h2b('123abc'), 'hash_prevouts': TEST_HASH_PREVOUTS,
                     'output_index': 0, 'value': 123}), 'extract asset_id'),
                  (('badcommit6a', 'get_commitments',
                    {'asset_id': b'', 'hash_prevouts': TEST_HASH_PREVOUTS,
                     'output_index': 0, 'value': 123}), 'extract asset_id'),
                  (('badcommit7', 'get_commitments',
                    {'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract hash_prevouts'),
                  (('badcommit8', 'get_commitments',
                    {'hash_prevouts': None, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract hash_prevouts'),
                  (('badcommit9', 'get_commitments',
                    {'hash_prevouts': 123, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract hash_prevouts'),
                  (('badcommit10', 'get_commitments',
                    {'hash_prevouts': 'notbin', 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract hash_prevouts'),
                  (('badcommit11', 'get_commitments',
                    {'hash_prevouts': '123abc', 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract hash_prevouts'),
                  (('badcommit12', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract output index'),
                  (('badcommit13', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': None,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract output index'),
                  (('badcommit14', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': '0',
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract output index'),
                  (('badcommit15', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 'X',
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), 'extract output index'),
                  (('badcommit16', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN}), 'extract value'),
                  (('badcommit17', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': '123'}), 'extract value'),
                  (('badcommit18', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123,
                     'vbf': b'123'}), 'extract vbf'),
                  (('badcommit19', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123,
                     'vbf': b'notbin'}), 'extract vbf'),
                  (('badcommit20', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123,
                     'vbf': b'123abc'}), 'extract vbf'),

                  (('badsignliq1', 'sign_liquid_tx'),  'Expecting parameters map'),
                  (('badsignliq2', 'sign_liquid_tx',
                    {'txn': GOODTX, 'num_inputs': 1,
                     'trusted_commitments': [{}, {}]}), 'extract valid network'),
                  (('badsignliq2a', 'sign_liquid_tx',
                    {'network': 'localtest-liquid',
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract tx'),
                  (('badsignliq2b', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': None,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract tx'),
                  (('badsignliq2c', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': b'',
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract tx'),
                  (('badsignliq3', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': 'notbin',
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract tx'),
                  (('badsignliq4', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': h2b('123abc'),
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract tx'),
                  (('badsignliq5', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'trusted_commitments': [{}, {}]}), 'valid number of inputs'),
                  (('badsignliq6', 'sign_liquid_tx',  # Wrong number of inputs
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 2, 'trusted_commitments': [{}, {}]}),
                   'Unexpected number of inputs'),
                  (('badsignliq7', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 'X', 'trusted_commitments': [{}, {}]}),
                   'valid number of inputs'),
                  (('badsignliq8', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': None, 'trusted_commitments': [{}, {}]}),
                   'valid number of inputs'),
                  (('badsignliq9', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': '0'}), 'valid number of inputs'),
                  (('badsignliq10', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': None}),
                   'extract trusted commitments'),
                  (('badsignliq11', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': 'notarray'}),
                   'extract trusted commitments'),
                  (('badsignliq12', 'sign_liquid_tx',  # Wrong number of commitments
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}]}),
                   'Unexpected number of trusted commitments'),
                  (('badsignliq13', 'sign_liquid_tx',  # Wrong number of commitments
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}, {}]}),
                   'Unexpected number of trusted commitments'),
                  (('badsignliq14', 'sign_liquid_tx',  # Empty commitments for blinded output
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}),
                   'Missing trusted commitment data for blinded output'),
                  (('badsignliq15', 'sign_liquid_tx',  # invalid network
                    {'network': 'made-up', 'txn': GOODTX, 'num_inputs': 1,
                     'trusted_commitments': [{}, {}],
                     'change': [{'path': [1, 2, 3]}]}), 'extract valid network'),
                  (('badsignliq16', 'sign_liquid_tx',  # wrong network type for call
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'trusted_commitments': [{}, {}],
                     'change': [{'path': [1, 2, 3]}, {}]}),
                   'only appropriate for liquid'),
                  (('badsignliq17', 'sign_liquid_tx',  # Bad change outputs
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': []}), 'Unexpected number of output entries'),
                  (('badsignliq18', 'sign_liquid_tx',  # paths missing
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': [{}, {}]}), 'Failed to extract valid receive path'),
                  (('badsignliq19', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET1]}), 'Invalid asset info passed'),
                  (('badsignliq20', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET2]}), 'Invalid asset info passed'),
                  (('badsignliq21', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET3]}), 'Invalid asset info passed'),
                  (('badsignliq22', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET4]}), 'Invalid asset info passed'),
                  (('badsignliq23', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET5]}), 'Invalid asset info passed')]

    if not LIQUID_DESCRIPTORS:
        bad_params.append(
            (('badsignliq24', 'sign_liquid_tx',
              {'network': 'localtest-liquid', 'txn': GOODTX,
               'num_inputs': 1, 'trusted_commitments': [{}, {}],
               'change': [{'descriptor_name': 'looksvalid', 'is_change': True,
                           'branch': 1, 'pointer': 13}, {}]}), 'not supported on liquid')
        )

    bad_liq_inputs = [(('badliqin1', 'tx_input'), 'Expecting parameters map'),
                      (('badliqin2', 'tx_input',
                        {'is_witness': True, 'path': [0]}), 'extract script'),
                      (('badliqin3', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': None}), 'extract script'),
                      (('badliqin4', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': 'notbin'}), 'extract script'),
                      (('badliqin5', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12')}),
                       'extract value commitment'),
                      (('badliqin6', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': 15200}), 'extract value commitment'),
                      (('badliqin7', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': 'notbin'}), 'extract value commitment'),
                      (('badliqin8', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': GOOD_COMMITMENT, 'sighash': 'SIGHASH_ALL'}),
                       'fetch valid sighash'),
                      (('badliqin9', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': GOOD_COMMITMENT, 'sighash': h2b('03')}),
                       'fetch valid sighash'),
                      (('badliqin10', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': GOOD_COMMITMENT, 'sighash': 300}),
                       'fetch valid sighash'),
                      (('badliqin11', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': GOOD_COMMITMENT, 'sighash': 0}),
                       'Unsupported sighash value'),
                      (('badliqin12', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': GOOD_COMMITMENT, 'sighash': 2}),
                       'Unsupported sighash value')]

    # Some bad commitment data is detected immediately... esp if it is
    # missing or not syntactically valid, unparseable etc.
    bad_commitments = [  # Field missing - note commitments are optional so not an error to omit
                        (_commitsMinus('asset_id'), 'trusted commitment'),
                        (_commitsMinus('value'), 'trusted commitment'),
                        (_commitsMinus('abf'), 'trusted commitment'),
                        (_commitsMinus('vbf'), 'trusted commitment'),
                        (_commitsMinus('blinding_key'), 'Missing trusted commitment'),
                        # Field bad type/length etc.
                        (_commitsUpdate('asset_id', 'notbin'), 'trusted commitment'),
                        (_commitsUpdate('asset_id', h2b('123abc')), 'trusted commitment'),
                        (_commitsUpdate('asset_id', b''), 'trusted commitment'),
                        (_commitsUpdate('value', 'notint'), 'trusted commitment'),
                        (_commitsUpdate('abf', 'notbin'), 'trusted commitment'),
                        (_commitsUpdate('abf', h2b('123abc')), 'trusted commitment'),
                        (_commitsUpdate('abf', b''), 'trusted commitment'),
                        (_commitsUpdate('vbf', 'notbin'), 'trusted commitment'),
                        (_commitsUpdate('vbf', h2b('123abc')), 'trusted commitment'),
                        (_commitsUpdate('vbf', b''), 'trusted commitment'),
                        (_commitsUpdate('asset_generator', 'notbin'), 'trusted commitment'),
                        (_commitsUpdate('asset_generator', '123abc'), 'trusted commitment'),
                        (_commitsUpdate('value_commitment', 'notbin'), 'trusted commitment'),
                        (_commitsUpdate('value_commitment', '123abc'), 'trusted commitment'),
                        (_commitsUpdate('blinding_key', 'notbin'), 'Missing trusted commitment'),
                        (_commitsUpdate('blinding_key', '123abc'), 'Missing trusted commitment'),
                        # Field bad value
                        (_commitsUpdate('asset_id', BADVAL32), 'verify trusted commitment data'),
                        (_commitsUpdate('abf', BADVAL32), 'verify trusted commitment'),
                        (_commitsUpdate('vbf', BADVAL32), 'verify trusted commitment'),
                        (_commitsUpdate('asset_generator', BADVAL33), 'verify trusted commitment'),
                        (_commitsUpdate('value_commitment', BADVAL33), 'verify trusted commitment'),
                        # Asset blind proof in place of abf
                        (_commitsAssetBlindProof(''), 'trusted commitment'),
                        (_commitsAssetBlindProof('notbin'), 'trusted commitment'),
                        (_commitsAssetBlindProof('123abc'), 'trusted commitment'),
                        (_commitsAssetBlindProof(b''), 'trusted commitment'),
                        # Value blind proof in place of vbf
                        (_commitsValueBlindProof(''), 'trusted commitment'),
                        (_commitsValueBlindProof('notbin'), 'trusted commitment'),
                        (_commitsValueBlindProof('123abc'), 'trusted commitment'),
                        (_commitsValueBlindProof(b''), 'trusted commitment')]
    if has_psram:
        # Invalid/incorrect explicit proofs
        bad_commitments.append((_commitsAssetBlindProof(BAD_ASSET_PROOF),
                               'Failed to verify explicit asset/value commitment proofs'))
        bad_commitments.append((_commitsValueBlindProof(BAD_VALUE_PROOF),
                               'Failed to verify explicit asset/value commitment proofs'))

    # Test all the simple cases
    for badmsg, errormsg in bad_params:
        _test_bad_params(jade, badmsg, errormsg)

    # Test all the bad tx commitments
    for badcommitment, errormsg in bad_commitments:
        badcommits = [badcommitment, {}]  # add a null for the unblind output
        _test_bad_params(jade,
                         ('signLiquid', 'sign_liquid_tx',
                          {'network': 'localtest-liquid',
                           'txn': GOODTX,
                           'num_inputs': 1,
                           'trusted_commitments': badcommits}),
                         errormsg)

    # Test all the bad tx inputs
    for badinput, errormsg in bad_liq_inputs:
        # Initiate a good sign-liquid-tx
        result = _test_good_params(jade,
                                   ('signLiquidInput', 'sign_liquid_tx',
                                    {'network': 'localtest-liquid',
                                     'txn': GOODTX,
                                     'num_inputs': 1,
                                     'trusted_commitments': GOOD_COMMITMENTS}))
        assert result is True

        # test a bad input
        _test_bad_params(jade, badinput, errormsg)


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
                         ('JADE_FREE_SPIRAM', 0),
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
        return check_mem_stats(jadeapi, startinfo, endinfo, has_psram, has_ble, strict,
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


# Helper to fetch the scriptpubkeys, assets and input values for sign_tx tests
def _get_signing_data(jadeapi, testcase, txn):
    test_input = testcase['input']
    is_liquid = 'liquid' in test_input['network']
    use_ae_signatures = test_input.get('use_ae_signatures', False)

    inputs = test_input['inputs']
    scriptpubkeys = wally.map_init(len(inputs), None)
    values = wally.map_init(len(inputs), None)
    assets = wally.map_init(len(inputs), None) if is_liquid else None
    for i, inputdata in enumerate(inputs):
        if not inputdata:
            pass  # No-op
        elif inputdata.get('input_tx'):
            # Bitcoin: Fetch info from the prevout for the input
            utxo_index = wally.tx_get_input_index(txn, i)
            utxo = wally.tx_from_bytes(inputdata['input_tx'], 0)
            wally.map_add_integer(scriptpubkeys, i, wally.tx_get_output_script(utxo, utxo_index))
            # Satoshi value (as uint64 native-endian bytes)
            value = wally.tx_get_output_satoshi(utxo, utxo_index)
            wally.map_add_integer(values, i, value.to_bytes(8, byteorder=sys.byteorder))
        elif is_liquid:
            # Liquid: Fetch info from the testcase
            if 'scriptpubkey' in inputdata:
                wally.map_add_integer(scriptpubkeys, i, inputdata['scriptpubkey'])
            if 'asset_generator' in inputdata:
                wally.map_add_integer(assets, i, inputdata['asset_generator'])
            if 'value_commitment' in inputdata:
                wally.map_add_integer(values, i, inputdata['value_commitment'])
        else:
            # Bitcoin: If no input_tx, sats can be passed instead (Deprecated).
            # Only valid for non-taproot, single-input segwit txns
            assert inputdata['is_witness']
            assert len(inputs) == 1
            # Satoshi value (as uint64 native-endian bytes)
            value = inputdata['satoshi']
            wally.map_add_integer(values, i, value.to_bytes(8, byteorder=sys.byteorder))
    return scriptpubkeys, assets, values


def _get_genesis(network):
    if 'liquid' not in network:
        return None
    if 'localtest' in network:
        genesis = '00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21'
    elif 'testnet' in network:
        genesis = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1'
    else:
        genesis = '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003'
    return bytes.fromhex(genesis)[::-1]


# Helper to verify a tx signature - handles checking an Anti-Exfil signature
# contains the entropy that was passed in by the host.
def _check_tx_signatures(jadeapi, testcase, rslt):
    assert len(rslt) == len(testcase['expected_output'])

    # Get txn-level details
    test_input = testcase['input']

    network = test_input['network']
    use_ae_signatures = test_input.get('use_ae_signatures', False)
    is_liquid = 'liquid' in network

    if is_liquid:
        # Liquid txn
        txn = wally.tx_from_bytes(test_input['txn'], wally.WALLY_TX_FLAG_USE_ELEMENTS)

        # Poke any commitment data into tx outputs
        for i, commitments in enumerate(test_input['trusted_commitments']):
            if commitments \
              and 'asset_generator' in commitments and 'value_commitment' in commitments:
                wally.tx_set_output_asset(txn, i, commitments['asset_generator'])
                wally.tx_set_output_value(txn, i, commitments['value_commitment'])
    else:
        # BTC tx, straightforward
        txn = wally.tx_from_bytes(test_input['txn'], 0)

    scriptpubkeys, assets, values = _get_signing_data(jadeapi, testcase, txn)
    cache = wally.map_init(16, None)  # TODO: Use a wally constant when available

    # Iterate over the results verifying each signature
    for i, (expected, actual) in enumerate(zip(testcase['expected_output'], rslt)):
        # NOTE: signatures returned have the sighash byte appended
        if use_ae_signatures:
            # Anti-Exfil signer_commitment and signature (might not be low-r, but should be low-s)
            assert tuple(expected) == actual, list(map(bytes.hex, actual))

            # Check sig length is low-s (ie. remove one from the possible max length)
            assert len(actual[1]) <= wally.EC_SIGNATURE_DER_MAX_LEN + 1 - 1  # sighash byte, low-s
            signer_commitment, signature = actual
        else:
            # Standard EC signature should be low-s and low-r
            assert actual == expected, f'{actual.hex()} != {expected.hex()} {testcase["filename"]}'

            # NOTE: low-s is implied/assumed here, so no need to remove one from max-len
            assert len(actual) <= wally.EC_SIGNATURE_DER_MAX_LOW_R_LEN + 1  # sighash byte, low-s
            signer_commitment, signature = None, actual  # No signer_commitment for EC sig

        if not len(signature):
            continue  # We didn't sign this input, ignore it

        # We signed this input, get the signature message hash (ie. the
        # hash value that was signed) and verify the signature against it
        inputdata = test_input['inputs'][i]
        script = inputdata['script']
        is_p2tr = script[0] == 0x51 and script[1] == 32  # OP_1 [32 byte xonly pubkey]
        def_sighash = wally.WALLY_SIGHASH_DEFAULT if is_p2tr else wally.WALLY_SIGHASH_ALL
        sighash = inputdata.get('sighash', def_sighash)
        if is_p2tr:
            sighash_type = wally.WALLY_SIGTYPE_SW_V1
            script = None  # Taproot uses the script in 'scriptpubkeys'
        elif inputdata['is_witness']:
            sighash_type = wally.WALLY_SIGTYPE_SW_V0
        else:
            sighash_type = wally.WALLY_SIGTYPE_PRE_SW

        key_version, codesep_pos, annex = 0, wally.WALLY_NO_CODESEPARATOR, None
        genesis = _get_genesis(network)
        msghash = wally.tx_get_input_signature_hash(
            txn, i, scriptpubkeys, assets, values, script, key_version,
            codesep_pos, annex, genesis, sighash, sighash_type, cache)

        # Check sighash and verify signature!
        if is_p2tr:
            # Either 64 byte default sig or 65 byte non-default with sighash byte appended
            if len(signature) == wally.EC_SIGNATURE_LEN:
                assert sighash == wally.WALLY_SIGHASH_DEFAULT
            else:
                assert len(signature) == wally.EC_SIGNATURE_LEN + 1
                assert sighash != wally.WALLY_SIGHASH_DEFAULT
                assert signature[-1] == sighash
            rawsig = signature[:wally.EC_SIGNATURE_LEN]  # Ignore any sighash byte
        else:
            # A DER encoded sig with sighash byte appended
            assert signature[-1] == sighash
            rawsig = wally.ec_sig_from_der(signature[:-1])  # truncate sighash byte

        host_entropy = inputdata.get('ae_host_entropy') if use_ae_signatures else None
        _verify_signature(jadeapi, network, msghash, inputdata['path'],
                          host_entropy, signer_commitment, rawsig, is_schnorr=is_p2tr)


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

    # Too much input test - sends a lot of data so only run
    # if not running over BLE (as would take a long time)
    if not isble and not args.spts:
        logger.info(f'Buffer overflow test - PSRAM: {has_psram}')
        test_too_much_input(jadeapi.jade, has_psram)

    # Negative tests
    if negative:
        logger.info('Negative tests')
        if not args.spts:
            # TODO: enable these tests for args.spts=true
            test_random_bytes(jadeapi.jade)
            test_very_bad_message(jadeapi.jade)
        test_bad_message(jadeapi.jade)
        test_split_message(jadeapi.jade)
        test_concatenated_messages(jadeapi.jade, do_wait=False)
        test_concatenated_messages(jadeapi.jade, do_wait=True)
        test_unknown_method(jadeapi.jade)
        test_unexpected_method(jadeapi.jade)
        test_bad_params(jadeapi.jade)
        test_bad_params_liquid(jadeapi.jade, has_psram, has_ble)

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
