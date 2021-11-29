import os
import time
import glob
import cbor
import copy
import json
import base64
import logging
import argparse
import subprocess
import threading
import _thread

from pinserver.server import PINServerECDH
from pinserver.pindb import PINDb
import wallycore as wally
from jadepy.jade import JadeAPI, JadeInterface, JadeError

# Enable jade logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jade-device')
device_logger.setLevel(logging.DEBUG)
device_logger.addHandler(jadehandler)


def h2b(hexdata):
    if hexdata is None:
        return None
    elif isinstance(hexdata, list):
        return list(map(h2b, hexdata))
    else:
        return bytes.fromhex(hexdata)


def _h2b_test_case(testcase):
    # Convert fields from hex to binary
    if 'txn' in testcase['input']:
        # sign-tx data
        testcase['input']['txn'] = h2b(testcase['input']['txn'])

        for inputdata in testcase['input']['inputs']:
            if 'input_tx' in inputdata:
                inputdata['input_tx'] = h2b(inputdata['input_tx'])
            if 'script' in inputdata:
                inputdata['script'] = h2b(inputdata['script'])
            if 'value_commitment' in inputdata:
                inputdata['value_commitment'] = h2b(inputdata['value_commitment'])
            if 'ae_host_commitment' in inputdata:
                inputdata['ae_host_commitment'] = h2b(inputdata['ae_host_commitment'])
            if 'ae_host_entropy' in inputdata:
                inputdata['ae_host_entropy'] = h2b(inputdata['ae_host_entropy'])

        if 'trusted_commitments' in testcase['input']:
            for commitment in testcase['input']['trusted_commitments']:
                if commitment:
                    for k, v in commitment.items():
                        commitment[k] = v if k == 'value' else h2b(v)

        if 'expected_output' in testcase:
            testcase['expected_output'] = h2b(testcase['expected_output'])

    elif 'message' in testcase['input']:
        # sign-msg test data
        if 'ae_host_commitment' in testcase['input']:
            testcase['input']['ae_host_commitment'] = h2b(testcase['input']['ae_host_commitment'])
        if 'ae_host_entropy' in testcase['input']:
            testcase['input']['ae_host_entropy'] = h2b(testcase['input']['ae_host_entropy'])

        if 'expected_output' in testcase and len(testcase['expected_output']) == 2:
            testcase['expected_output'][0] = h2b(testcase['expected_output'][0])

    if 'multisig_name' in testcase['input']:
        # multisig data
        for signer in testcase['input']['descriptor']['signers']:
            signer['fingerprint'] = h2b(signer['fingerprint'])

    return testcase


# Helper to read a json file into a dict
def _read_json_file(filename):
    logger.info('Reading json file: {}'.format(filename))
    with open(filename, 'r') as json_file:
        return json.load(json_file)


# Helper to read json test files into a list
def _get_test_cases(pattern):
    return (_h2b_test_case(_read_json_file(f)) for f in glob.glob("./test_data/" + pattern))


# Helper to compare two dicts
def _dicts_eq(lhs, rhs):
    return cbor.dumps(lhs, sort_keys=True) == cbor.dumps(rhs, sort_keys=True)


BLE_TEST_PASSKEYFILE = "ble_test_passkey.txt"
BLE_TEST_BADKEYFILE = "ble_test_badkey.txt"

# The default serial device, and the serial read timeout
DEFAULT_SERIAL_DEVICE = "/dev/ttyUSB0"
SRTIMEOUT = 30

# The pubkey for the test (in-proc) pinserver
PINSERVER_TEST_PUBKEY_FILE = "server_public_key.pub"

# Pinserver prod defaults
PINSERVER_DEFAULT_URL = "https://jadepin.blockstream.com"
PINSERVER_DEFAULT_ONION = "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion"

# The number of values expected back in version info
NUM_VALUES_VERINFO = 19

TEST_MNEMONIC = 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana'

TEST_MNEMONIC_12 = 'retire verb human ecology best member fiction measure \
demand stereo wedding olive'

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

GET_GREENADDRESS_DATA = [('localtest', 0, 1, 345, None, 0, '2MyMy6Ey7a5dmWJW1D\
9M7RFwjmXD1ECrgy4'),
                         ('testnet', 0, 1, 568, None, 51840, '2MxbBuvnRvgL3uTD\
tTkufPTdzuwuXE9HCNj'),
                         ('mainnet', 3, 1, 88, '', 0, '36kTtrBFR5NQmzBxAuNWcmL\
k22WsuhRq2S'),
                         ('mainnet', 0, 1, 568, 'xpub6BYx1MizD2XPpY6EuF5Pso8cG\
5fVHJEWniziGqXcrrcqH96MUiPcuNQkfKSnGx9tCvBJBZx35fiZE3zBbVkZqH89TU4W6HkyE9fSUx9\
QHNX', 0, '338M4PG24m1gZggrzQV1s9vr3dZZ31kLsU'),
                         ('localtest-liquid', 6, 1, 345, None, 65535, 'Azpx2UG\
RpzEQ6pt6yCbPYGnjqNaTtxN2ZdLmMMjWMVvJdzd5uD9cysaRc4Es5auve68RAwijQqReG3AT'),
                         ('testnet-liquid', 3, 1, 244, None, 65535, 'vjU6NdME2\
viTa8BzBA6qNG5jQKLfGfLvC93f4fRwZ9SR4pE7KBWQNbGUi2bodfxiMACFDombViiC5Vej'),
                         ('liquid', 10, 1, 122, None, 65535, 'VJLGotGqjthW3NY7\
JFZ7EaJZo8rnuRi23waPVY7FwJTYxtFNrNLy6CC4VEQoKRmd5VkL2mmuo64LfZNy')]

GET_SINGLE_SIG_ADDR_DATA = [  # The below were generated on core
                            ('localtest', 'sh(wpkh(k))',
                             [2147483648, 2147483648, 2147483657],
                             '2N8Yn3oXF7Pg38yBpuvoheDS7981vW4vy5b'),
                            ('localtest', 'wpkh(k)',
                             [2147483648, 2147483648, 2147483658],
                             'bcrt1qkrkcltr7kx5s5alsvnpvkcfunlrjtwx942zmn4'),
                            ('localtest', 'pkh(k)',
                             [2147483648, 2147483648, 2147483659],
                             'mwJDHFp93fuHZysBwU7RTiFXrJZXXcPuUc'),
                            # And these on elements ...
                            ('localtest-liquid', 'sh(wpkh(k))',
                             [2147483648, 2147483648, 2147483649],
                             'AzpnFQq17AnWm4gvL2oHLRucFawmq8VWFyaxfPX3EgrihEdw\
DXWmb1QmA7QrRu5RCy3wDtSe8h9WxKbQ'),
                            ('localtest-liquid', 'wpkh(k)',
                             [2147483648, 2147483648, 2147483650],
                             'el1qqwud2rtjxwgfxc9wrey504mtjqujrmzsc442zway65gk\
uj2f0mm4xfv8h3sqfz223jxjrj307zyqln2dywxmsvpvs9x2tvufj'),
                            ('localtest-liquid', 'pkh(k)',
                             [2147483648, 2147483648, 2147483651],
                             'CTEuAWMSL94hM2PbTzoe8TGLjyVkkSgdPFas7eUMouiGk5Q2\
SfzadGnGduPwvoVK1ZpthykJup8A8Eh2'),

                            # The below are 'speculative' ...
                            ('mainnet', 'sh(wpkh(k))',
                             [2147483648, 2147483648, 2147483657],
                             '3GzZz4bDVwAgwBZHEoBq2GSqvmokj9e4Jx'),
                            ('mainnet', 'wpkh(k)',
                             [2147483648, 2147483648, 2147483657],
                             'bc1qpky3r9yuz5gguvuqkrf2dfqtqgutr9evgnjmq6'),
                            ('mainnet', 'pkh(k)',
                             [2147483648, 2147483648, 2147483657],
                             '12EZzC9ck31rxaFYKbGwVj1gYXsUwfHuWj'),

                            ('testnet', 'sh(wpkh(k))',
                             [2147483648, 2147483648, 2147483657],
                             '2N8Yn3oXF7Pg38yBpuvoheDS7981vW4vy5b'),
                            ('testnet', 'wpkh(k)',
                             [2147483648, 2147483648, 2147483657],
                             'tb1qpky3r9yuz5gguvuqkrf2dfqtqgutr9evz4fgmf'),
                            ('testnet', 'pkh(k)',
                             [2147483648, 2147483648, 2147483657],
                             'mgkXHFEbZ4T7jgjA3AFKKeE1QXUBrX7qQC'),

                            ('liquid', 'sh(wpkh(k))',
                             [2147483648, 2147483648, 2147483657],
                             'VJLGcUjN2q6HHuNUAQJ2LEASQnr5LkD2DgDwT2vcyQjKhA3B\
5a2VAgp94Gj5rSXYiD6eHmGJmVSHY5xG'),
                            ('testnet-liquid', 'wpkh(k)',
                             [2147483648, 2147483648, 2147483657],
                             'tlq1qq28n8pj790vsyd6t5lr6n0puhrp7hd8wvcgrlm8knxm\
684lxq6pzjrvfzx2fc9gs3cecpvxj56jqkq3ckxtjc88gqxa6j2cv7'),
                            ('localtest-liquid', 'pkh(k)',
                             [2147483648, 2147483648, 2147483657],
                             'CTEjtdpkvj7mrGtgMTrmDfSnH9DdN9Rzi2tzsxsFNujSU8qh\
YzNnQaWx24j5hX8iWcaZgTZJ6Y3sedLi')]

# Hold test data in separate files as can be large
MULTI_REG_TESTS = _get_test_cases("multisig_reg_*.json")
MULTI_REG_SS_TESTS = _get_test_cases("multisig_reg_ss_*.json")
SIGN_MSG_TESTS = _get_test_cases("msg_*.json")
SIGN_TXN_TESTS = _get_test_cases("txn_*.json")
SIGN_TXN_FAIL_CASES = _get_test_cases("badtxn_*.json")
SIGN_LIQUID_TXN_TESTS = _get_test_cases("liquid_txn_*.json")
SIGN_SINGLE_SIG_TESTS = _get_test_cases("singlesig_txn*.json")
SIGN_SINGLE_SIG_LIQUID_TESTS = _get_test_cases("singlesig_liquid_txn*.json")

TEST_SCRIPT = h2b('76a9145f4fcd4a757c2abf6a0691f59dffae18852bbd7388ac')

EXPECTED_MASTER_BLINDING_KEY = h2b('afacc503637e85da661ca1706c4ea147f1407868c4\
8d8f92dd339ac272293cdc')

EXPECTED_BLINDING_KEY = h2b('023454c233497be73ed98c07d5e9069e21519e94d0663375c\
a57c982037546e352')

TEST_THEIR_PK = h2b('03e7cd9230b30bf53753a43add0e88931bac3be21baa4c6465d9f8da9\
251f2904c')

EXPECTED_SHARED_SECRET = h2b('35801ebd1e62e8698490440861cff2e5bd10cf4aec19b51f\
8ccc7dc910a7e488')

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
                             'hmac': h2b('385af94c60ce6395b7aae2b09eef73d46ac5\
7a209674101e295c0b8129a60672'),
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
                             'hmac': h2b('73c9e1134ee72d667972ac7eeb97c535f318\
885589acd4ba7577f65ac4c80c52'),
                             'asset_id': h2b('5ac9f65c0efcc4775e0baec4ec03abdd\
e22473cd3cf33c0419ca290e0751b225'),
                             'value': 9000000}


# The tests
def test_bad_message(jade):
    bad_requests = [{'method': 'get_version_info'},  # no-id
                    {'id': '2'},               # no method
                    {'id': 123},               # bad id type
                    {'id': '12345'*8},         # id too long
                    {'method': 'x'*40, 'id': '4'}]   # method

    for request in bad_requests:
        jade.write_request(request)
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
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'] == 'Invalid RPC Request message'
        assert 'result' not in reply


def test_very_bad_message(jade):
    empty = cbor.dumps(b"")
    text = cbor.dumps("This is not a good cbor message")
    truncated = cbor.dumps("{'id': '1', method: 'msgwillbecut'}")[1:]

    for msg in [empty, text, truncated]:
        jade.write(msg)
        reply = jade.read_response()

        # Returned id should be '00'
        assert reply['id'] == '00'

        # Assert bad message response
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'] == 'Invalid RPC Request message'
        assert 'result' not in reply


def test_too_much_input(jade, has_psram):
    noise = 'long'.encode()   # 4b
    cacophony = noise * 4096  # 16k

    # NOTE: if the hw has PSRAM it will have a 401k buffer.
    # If not, it will have a 17k buffer.  Want only 1k left.
    # Send the appropriate amount of noise. (400k or 16k)
    for _ in range(25 if has_psram else 1):  # 25x16 is 400k
        jade.write(cacophony)

    # Input buffer should now only have 1k space remaining.
    # Send another 1k to fill/overflow the buffers, then another 128b
    din = noise * 288         # 4x288 = 1024 + 128 = 1152
    jade.write(din)

    # No response expected
    # Expect first 17k/401k (ie. buffer-size) to be discarded

    # Send eol/end-of-msg, should get error back about remainder  -
    # 128 bytes plus the 'xyz\n' = 132bytes
    jade.write('xyz\n'.encode())
    reply = jade.read_response()

    # Expect error
    error = reply['error']
    assert error['code'] == JadeError.INVALID_REQUEST
    assert error['message'] == 'Invalid RPC Request message'
    assert len(error['data']) == 132  # the bytes not discarded
    assert error['data'].endswith(b'longxyz\n')


def test_split_message(jade):
    # Simulate transport stream being v.slow
    msg = cbor.dumps({'method': 'get_version_info', 'id': '24680'})
    for msgpart in [msg[:5], msg[5:10], msg[10:]]:
        jade.write(msgpart)
        time.sleep(0.25)

    reply = jade.read_response()

    # Returned id should match sent
    assert reply['id'] == "24680"
    assert 'error' not in reply
    assert 'result' in reply and len(reply['result']) == NUM_VALUES_VERINFO


def test_concatenated_messages(jade):
    # Simulate a 'bad' client sending two messages without waiting for a reply
    msg1 = {'method': 'get_version_info', 'id': '123456'}
    msg2 = {'method': 'get_version_info', 'id': '456789'}
    concat_cbor = cbor.dumps(msg1) + cbor.dumps(msg2)
    jade.write(concat_cbor)

    reply1 = jade.read_response()
    reply2 = jade.read_response()

    # Returned ids should match sent
    for msg, reply in [(msg1, reply1), (msg2, reply2)]:
        assert reply['id'] == msg['id']
        assert 'error' not in reply
        assert 'result' in reply and len(reply['result']) == NUM_VALUES_VERINFO


def test_unknown_method(jade):
    # Includes tests of method prefixes 'get...' and 'sign...'
    for msgid, method in [('unk0', 'dostuff'), ('unk1', 'get'), ('unk2', 'sign')]:
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
    unexpected = [('protocol1', 'handshake_init',
                   {'ske': 'abcdef', 'sig': '1234'}),
                  ('protocol2', 'handshake_complete',
                   {'payload': 'abcdef', 'hmac': '1234'}),
                  ('protocol3', 'ota_data', h2b('abcdef')),
                  ('protocol4', 'ota_complete'),
                  ('protocol5', 'tx_input'),
                  ('protocol6', 'get_signature')]

    for args in unexpected:
        request = jade.build_request(*args)
        reply = jade.make_rpc_call(request)

        # Assert protocol-error/unexpected-method response
        error = reply['error']
        assert error['code'] == JadeError.PROTOCOL_ERROR
        assert error['message'] == 'Unexpected method'
        assert 'result' not in reply


def _test_good_params(jade, args):
    request = jade.build_request(*args)
    reply = jade.make_rpc_call(request)

    # Assert all-good response
    assert reply['id'] == request['id']
    assert 'error' not in reply
    assert 'result' in reply
    return reply['result']


def _test_bad_params(jade, args, expected_error):
    request = jade.build_request(*args)
    reply = jade.make_rpc_call(request)

    # Assert bad-parameters response
    assert reply['id'] == request['id']
    assert 'result' not in reply
    assert 'error' in reply
    error = reply['error']
    assert error['code'] == JadeError.BAD_PARAMETERS
    assert 'message' in error
    assert expected_error in error['message']

    return error['message']


def test_bad_params(jade):
    pubkey1, sig1 = PINServerECDH().get_signed_public_key()
    pubkey2, sig2 = PINServerECDH().get_signed_public_key()

    GOODTX = h2b(
             '02000000010f757ae0b5714cb36e017dfffafe5f3ba8c89ddb969a0ae60\
d99ee7b5892a2740000000000ffffffff01203f0f00000000001600145f4fcd4a757c2abf6a069\
1f59dffae18852bbd7300000000')

    GOOD_COSIGNERS = [
        {
          "fingerprint": h2b("1273da33"),
          "derivation": [44, 2147483648, 2147483648],
          "xpub": "tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3\
GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG",
          "path": [3, 1]
        },
        {
          "fingerprint": h2b("e3ebcc79"),
          "derivation": [2147483651, 2147483649, 1],
          "xpub": "tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8\
epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka",
          "path": [1]
        }
    ]
    bad_cosigners1 = copy.deepcopy(GOOD_COSIGNERS)
    bad_cosigners1[0]['fingerprint'] = bad_cosigners1[1]['fingerprint']
    bad_cosigners2 = copy.deepcopy(GOOD_COSIGNERS)
    bad_cosigners2[1]['fingerprint'] = bad_cosigners2[0]['fingerprint']
    bad_cosigners3 = copy.deepcopy(GOOD_COSIGNERS)
    bad_cosigners3[1]['derivation'] = [1, 2, 3, 4]
    bad_cosigners4 = copy.deepcopy(GOOD_COSIGNERS)
    bad_cosigners4[1]['path'] = [2147483648]

    bad_params = [(('badauth1', 'auth_user'), 'Expecting parameters map'),
                  (('badauth2', 'auth_user', {'network': None}), 'extract valid network'),
                  (('badauth3', 'auth_user', {'network': 1234512345}), 'extract valid network'),
                  (('badauth4', 'auth_user', {'network': ''}), 'extract valid network'),
                  (('badauth5', 'auth_user', {'network': 'notanetwork'}), 'extract valid network'),

                  (('badpin1', 'update_pinserver'), 'Expecting parameters map'),
                  (('badpin2', 'update_pinserver',
                    {'urlB': 'testurl'}), 'only set second URL if also setting first'),
                  (('badpin3', 'update_pinserver',
                    {'urlA': 'testurl', 'urlB': 'testonion', 'reset_details': True}),
                   'both set and reset pinserver details'),
                  (('badpin4', 'update_pinserver',
                    {'pubkey': h2b('abc123'), 'reset_details': True}),
                   'both set and reset pinserver details'),
                  (('badpin5', 'update_pinserver',
                    {'pubkey': h2b('abcdef')}), 'pinserver pubkey without setting URL'),
                  (('badpin6', 'update_pinserver',
                    {'urlA': 'testurl', 'urlB': 'testonion', 'pubkey': h2b('abcdef1234')}),
                   'extract valid pubkey'),
                  (('badpin7', 'update_pinserver',
                    {'certificate': 'testcert', 'reset_certificate': True}),
                   'set and reset pinserver certificate'),

                  (('badent1', 'add_entropy'), 'Expecting parameters map'),
                  (('badent2', 'add_entropy', {'entropy': None}), 'valid entropy bytes'),
                  (('badent3', 'add_entropy', {'entropy': 1234512345}), 'valid entropy bytes'),
                  (('badent4', 'add_entropy', {'entropy': ''}), 'valid entropy bytes'),
                  (('badent5', 'add_entropy', {'entropy': 'notbinary'}), 'valid entropy bytes'),

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
                  (('badxpub10', 'get_xpub', {'path': [1, 2, 3]}), 'valid network'),
                  (('badxpub11', 'get_xpub',  # network missing or invalid
                    {'path': [], 'network': 'invalid'}), 'valid network'),
                  (('badxpub12', 'get_xpub',  # network missing or invalid
                    {'path': [1, 2, 3], 'network': 'invalid'}), 'valid network'),

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
                      'variant': 'sh(multi(k))', 'signers': []}}), 'Invalid multisig threshold'),
                  (('badmulti9', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 0, 'signers': []}}),
                   'Invalid multisig threshold'),
                  (('badmulti10', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 12, 'signers': []}}),
                   'Invalid multisig threshold'),
                  (('badmulti11', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 5, 'signers': GOOD_COSIGNERS}}),
                   'threshold for number of co-signers'),
                  (('badmulti12', 'register_multisig',  # network missing or invalid
                    {'network': 'noexist', 'multisig_name': 'test'}), 'valid network'),
                  (('badmulti13', 'register_multisig',  # network missing or invalid
                    {'network': 'liquid', 'multisig_name': 'test'}), 'not supported for liquid'),
                  (('badmulti14', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2, 'signers': bad_cosigners1}}),
                  'validate multisig co-signers'),
                  (('badmulti15', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2, 'signers': bad_cosigners2}}),
                  'validate multisig co-signers'),
                  (('badmulti16', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2, 'signers': bad_cosigners3}}),
                  'validate multisig co-signers'),
                  (('badmulti17', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(multi(k))', 'threshold': 2, 'signers': bad_cosigners4}}),
                  'validate multisig co-signers'),

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
                    {'path': [1, 2, 3], 'variant': 'p2pkh',
                     'network': 'testnet'}), 'Invalid script variant parameter'),
                  (('badrecvaddr14', 'get_receive_address',
                    {'paths': [[1], [2, 3]], 'multisig_name': 'does not exist',
                     'network': 'testnet'}), 'Cannot find named multisig wallet'),
                  (('badrecvaddr15', 'get_receive_address',
                    {'paths': [[1], [2, 3]], 'multisig_name': 'whatever',
                     'network': 'liquid'}), 'not supported for liquid'),

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
                     'change': []}), 'Unexpected number of output (change) entries'),
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
                  (('badsigntx14', 'sign_tx',  # bad multisig name
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'multisig_name': 'bad',
                                 'paths': [[1, 2, 3]]}]}), 'Cannot find named multisig wallet'),
                  (('badsigntx15', 'sign_tx',
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [{'not_path': [1, 2, 3]}]}), 'extract valid change path'),
                  (('badsigntx16', 'sign_tx',  # wrong number of outputs
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'change': [None, None]}), 'Unexpected number of output (change) entries')]

    bad_tx_inputs = [(('badinput0', 'tx_input'), 'Expecting parameters map'),
                     (('badinput1', 'tx_input',
                       {'is_witness': True, 'satoshi': 120, 'path': []}), 'extract valid path'),
                     (('badinput2', 'tx_input',  # path too long
                       {'is_witness': True, 'satoshi': 120, 'path': [0, 1, 2] * 6}),
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
                       {'is_witness': False, 'input_tx': ''}), 'extract input_tx'),
                     (('badinput10', 'tx_input',
                       {'is_witness': False, 'input_tx': 'notbin'}), 'extract input_tx'),
                     (('badinput11', 'tx_input',  # odd number of hex chars
                       {'is_witness': False, 'input_tx': 'abc'}), 'extract input_tx')]

    # Test all the simple cases
    for badmsg, errormsg in bad_params:
        _test_bad_params(jade, badmsg, errormsg)

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


def test_bad_params_liquid(jade):

    GOODTX = h2b(
             '0200000000012413047d152348db4342763a0eece0d99e6e2983b3b46eda07ed\
e58d28f201ad0100000000ffffffff020a2b712848b6f14697590b06622266e8d82cb06030896d\
e79700b15562a20834fb0881e4ace4be80524bcc4f566e46a452ab5f43a49929cbf5743d9e1de8\
79a478a7033fc2cd1c4ce77e4339984f786dba6591bd862cf397e8cb6a99e457e162cad68617a9\
142e0ef2990318d8c9f7cee627650ba2a84fdda449870125b251070e29ca19043cf33ccd7324e2\
ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000f4240000000000000')

    GOODTX_INPUT = ('goodinput', 'tx_input',
                    {'is_witness': False, 'path': [0], 'script': h2b('ABCD')})

    GOOD_COMMITMENT = EXPECTED_LIQ_COMMITMENT_2.copy()
    GOOD_COMMITMENT['blinding_key'] = EXPECTED_BLINDING_KEY

    BAD_SHA256_VAL = EXPECTED_LIQ_COMMITMENT_1['hmac']
    BAD_COMMIT_VAL = EXPECTED_LIQ_COMMITMENT_1['value_commitment']

    def _commitsMinus(key):
        commits = GOOD_COMMITMENT.copy()
        del commits[key]
        return commits

    def _commitsUpdate(key, val):
        commits = GOOD_COMMITMENT.copy()
        commits[key] = val
        return commits

    bad_params = [(('badblindkey1', 'get_blinding_key'), 'Expecting parameters map'),
                  (('badblindkey2', 'get_blinding_key', {'script': None}), 'extract script'),
                  (('badblindkey3', 'get_blinding_key', {'script': 123}), 'extract script'),
                  (('badblindkey4', 'get_blinding_key', {'script': 'notbin'}), 'extract script'),

                  (('badnonce1', 'get_shared_nonce'), 'Expecting parameters map'),
                  (('badnonce2', 'get_shared_nonce',
                    {'script': TEST_SCRIPT}), 'extract their_pubkey'),
                  (('badnonce3', 'get_shared_nonce',
                    {'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce4', 'get_shared_nonce',
                    {'script': 123, 'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce5', 'get_shared_nonce',
                    {'script': 'notbin', 'their_pubkey': TEST_THEIR_PK}), 'extract script'),
                  (('badnonce6', 'get_shared_nonce',
                    {'script': TEST_SCRIPT, 'their_pubkey': 123}), 'extract their_pubkey'),
                  (('badnonce7', 'get_shared_nonce',
                    {'script': TEST_SCRIPT, 'their_pubkey': 'notbin'}), 'extract their_pubkey'),
                  (('badnonce8', 'get_shared_nonce',  # short pubkey
                    {'script': TEST_SCRIPT, 'their_pubkey': h2b('ab')}), 'extract their_pubkey'),
                  (('badnonce9', 'get_shared_nonce',  # bad 'include_pubkey'
                    {'script': TEST_SCRIPT, 'their_pubkey': TEST_THEIR_PK,
                     'include_pubkey': 'True'}), 'extract valid pubkey flag'),

                  (('badblindfac1', 'get_blinding_factor'), 'Expecting parameters map'),
                  (('badblindfac2', 'get_blinding_factor',
                    {'output_index': 0, 'type': 'ASSET'}), 'extract hash_prevouts'),
                  (('badblindfac3', 'get_blinding_factor',
                    {'hash_prevouts': 123, 'output_index': 0,
                     'type': 'ASSET'}), 'extract hash_prevouts'),
                  (('badblindfac4', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'type': 'ASSET',
                     'output_index': None}), 'extract output index'),
                  (('badblindfac5', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'type': 'ASSET',
                     'output_index': '3'}), 'extract output index'),
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
                     'type': 'ASSETXYZ'}), 'extract blinding factor type'),
                  (('badblindfac11', 'get_blinding_factor',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 0,
                     'type': 'VALUEVERYBAD'}), 'extract blinding factor type'),

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
                    {'asset_id': '123abc', 'hash_prevouts': TEST_HASH_PREVOUTS,
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
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), ''),
                  (('badcommit15', 'get_commitments',
                    {'hash_prevouts': TEST_HASH_PREVOUTS, 'output_index': 'X',
                     'asset_id': TEST_REGTEST_BITCOIN, 'value': 123}), ''),
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
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract txn'),
                  (('badsignliq2b', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': None,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract txn'),
                  (('badsignliq2c', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': b'',
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract txn'),
                  (('badsignliq3', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': 'notbin',
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract txn'),
                  (('badsignliq4', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': '123abc',
                     'num_inputs': 1, 'trusted_commitments': [{}, {}]}), 'extract txn'),
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
                   'Missing commitments data for blinded output'),
                  (('badsignliq15', 'sign_liquid_tx',  # invalid network
                    {'network': 'made-up', 'txn': GOODTX, 'num_inputs': 1,
                     'trusted_commitments': [{}, {}],
                     'change': [{'path': [1, 2, 3]}]}), 'extract valid network'),
                  (('badsignliq16', 'sign_liquid_tx',  # wrong network type for call
                    {'network': 'testnet', 'txn': GOODTX, 'num_inputs': 1,
                     'trusted_commitments': [{}, {}],
                     'change': [{'path': [1, 2, 3]}, {}]}),
                   'only appropriate for liquid'),
                  (('badsignliq17', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX, 'num_inputs': 1,
                     'trusted_commitments': [{}, {}],
                     'change': [{'multisig_name': 'not-allowed', 'paths': [[1, 2, 3]]}, {}]}),
                   'Multisig is not supported for liquid'),
                  (('badsignliq18', 'sign_liquid_tx',  # Bad change outputs
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': []}), 'Unexpected number of output (change) entries'),
                  (('badsignliq19', 'sign_liquid_tx',  # paths missing
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': [{}, {}]}), 'extract valid change path')]

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
                      (('badliqin5', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': 15200}), 'extract value commitment'),
                      (('badliqin5', 'tx_input',
                        {'is_witness': True, 'path': [0], 'script': h2b('abcd12'),
                         'value commitment': 'notbin'}), 'extract value commitment')]

    # Some bad commitment data is detected immediately... esp if it is
    # missing or not syntactically valid, unparseable etc.
    bad_early_commits = [_commitsMinus('asset_id'),
                         _commitsMinus('value'),
                         _commitsMinus('asset_generator'),
                         _commitsMinus('value_commitment'),
                         _commitsMinus('blinding_key'),
                         _commitsUpdate('asset_id', 'notbin'),
                         _commitsUpdate('asset_id', '123abc'),
                         _commitsUpdate('value', 'notint'),
                         _commitsUpdate('asset_generator', 'notbin'),
                         _commitsUpdate('asset_generator', '123abc'),
                         _commitsUpdate('value_commitment', 'notbin'),
                         _commitsUpdate('value_commitment', '123abc'),
                         _commitsUpdate('blinding_key', 'notbin'),
                         _commitsUpdate('blinding_key', '123abc'),
                         _commitsMinus('hmac'),
                         _commitsUpdate('hmac', 'notbin'),
                         _commitsUpdate('hmac', '123abc')]

    # ... other bad commitment data is not detected until after the inputs are
    # received and processed (bad values that mean hmac not correct)

    bad_late_commits = [_commitsUpdate('asset_id', BAD_SHA256_VAL),
                        _commitsUpdate('asset_generator', BAD_COMMIT_VAL),
                        _commitsUpdate('hmac', BAD_SHA256_VAL),
                        _commitsUpdate('value_commitment', BAD_COMMIT_VAL)]

    # Test all the simple cases
    for badmsg, errormsg in bad_params:
        _test_bad_params(jade, badmsg, errormsg)

    # Test all the bad tx inputs
    for badinput, errormsg in bad_liq_inputs:
        # Initiate a good sign-liquid-tx
        commits = [GOOD_COMMITMENT, {}]  # add a null for the unblind output
        result = _test_good_params(jade,
                                   ('signLiquid', 'sign_liquid_tx',
                                    {'network': 'localtest-liquid',
                                     'txn': GOODTX,
                                     'num_inputs': 1,
                                     'trusted_commitments': commits}))
        assert result is True

        # test a bad input
        _test_bad_params(jade, badinput, errormsg)

    # Test all the bad tx commitments
    for badcommitment in bad_early_commits:
        badcommits = [badcommitment, {}]  # add a null for the unblind output
        _test_bad_params(jade,
                         ('signLiquid', 'sign_liquid_tx',
                          {'network': 'localtest-liquid',
                           'txn': GOODTX,
                           'num_inputs': 1,
                           'trusted_commitments': badcommits}),
                         'trusted commitments from parameters')

    for badcommitment in bad_late_commits:
        # Message should be accepted as commitments element is well formed
        # but should be seen to be invalid later.
        badcommits = [badcommitment, None]  # add a null for the unblind output
        result = _test_good_params(jade,
                                   ('signLiquid', 'sign_liquid_tx',
                                    {'network': 'localtest-liquid',
                                     'txn': GOODTX,
                                     'num_inputs': 1,
                                     'trusted_commitments': badcommits}))
        assert result is True

        # Send in a valid input but should get a bad-params from the commitment
        _test_bad_params(jade, GOODTX_INPUT, 'from commitments data')


def test_passphrase(jade):
    def _set_wallet(passphrase=None):
        # Set mnemonic
        request = jade.build_request("id_mnem", "debug_set_mnemonic",
                                     {"mnemonic": TEST_MNEMONIC,
                                      "passphrase": passphrase})
        reply = jade.make_rpc_call(request)
        assert reply['id'] == request['id']
        assert 'error' not in reply
        assert reply['result'] is True

        # Get root xpub
        request = jade.build_request("id_xpub", "get_xpub",
                                     {"network": "mainnet",
                                      "path": []})
        reply = jade.make_rpc_call(request)
        assert reply['id'] == request['id']
        assert 'error' not in reply
        assert reply['result'].startswith('xpub')
        return reply['result']

    # Set mnemonic with/without a passphrase, and get root xpub
    xpub0 = _set_wallet(passphrase=None)
    xpub1 = _set_wallet(passphrase="Passphrase1")
    xpub2 = _set_wallet(passphrase="Passphrase2")

    # Check root xpubs are not the same
    # ie. that the passphrase leads to a different wallet
    assert xpub0 != xpub1 and xpub1 != xpub2 and xpub2 != xpub0

    # Check that using the same passphrase does get the same wallet
    xpub0_again = _set_wallet(passphrase=None)
    xpub1_again = _set_wallet(passphrase="Passphrase1")
    xpub2_again = _set_wallet(passphrase="Passphrase2")

    assert xpub0_again == xpub0 and xpub1_again == xpub1 and xpub2_again == xpub2


# Pinserver handshake test - note this is tightly coupled to the dedicated
# test handler in the hardware code (main/process/debug_handshake.c)
def test_handshake(jade):
    # First override the hww pinserver pubkey to match the local test key
    TEST_URL = 'https://this.is.a.test.url.com'
    TEST_ONION = 'http://we.dont.know.our.onion.but.this.string.is.about.the.right.size'
    TEST_CERT = 'tstcert.'*250  # ~2k should be representative of cert size
    with open(PINSERVER_TEST_PUBKEY_FILE, 'rb') as f:
        pubkey = f.read()
    msg = jade.build_request('dbg_pnsvr', 'update_pinserver',
                             {'urlA': TEST_URL,
                              'urlB': TEST_ONION,
                              'pubkey': pubkey,
                              'certificate': TEST_CERT})
    reply = jade.make_rpc_call(msg)
    assert reply['result'] is True

    # server provides a signed (with a static key) an ephemeral server key
    # exchange (ske) client validates it and provides a client key exchange
    # (cke) and because the server went first the client also provides an
    # encrypted (and hmaced) and signed piece of data that provides the server
    # with the actual request, to setup a PIN (pubkey, pinsecret) -> aes key
    # the aes key is hmac with some 32 byte random from the client and some 32
    # from the server

    # A: a test of 'set-pin' (ie. after user has initialised with a mnemonic)

    # 1. trigger the dedicated test case handler
    #    it should test 'set pin' first
    msg = jade.build_request('debugA1', 'debug_handshake')
    reply = jade.make_rpc_call(msg)
    result = reply['result']
    assert list(result.keys()) == ['http_request'], result.keys()
    assert list(result['http_request'].keys()) == ['params', 'on-reply']
    assert result['http_request']['on-reply'] == 'handshake_init'
    assert list(result['http_request']['params'].keys()) == \
        ['urls', 'root_certificates', 'method', 'accept', 'data']
    assert result['http_request']['params']['accept'] == 'json'
    assert result['http_request']['params']['method'] == 'POST'
    urls = result['http_request']['params']['urls']
    assert urls == [TEST_URL+'/start_handshake', TEST_ONION+'/start_handshake']
    certs = result['http_request']['params']['root_certificates']
    assert certs == [TEST_CERT]

    # 2. This is where the app would call the URL returned, and pass the
    #    response (ecdh key) to jade.  We use the pinserver class directly.
    #    The response from jade is the encrypted pin packet and the URL.
    server = PINServerECDH()
    pubkey, sig = server.get_signed_public_key()

    msg = jade.build_request(
                        'initA2', 'handshake_init',
                        {'ske': wally.hex_from_bytes(pubkey),
                         'sig': wally.hex_from_bytes(sig)})
    reply = jade.make_rpc_call(msg)
    result = reply['result']

    assert list(result.keys()) == ['http_request'], result.keys()
    assert list(result['http_request'].keys()) == ['params', 'on-reply']
    assert result['http_request']['on-reply'] == 'handshake_complete'
    assert list(result['http_request']['params'].keys()) == \
        ['urls', 'root_certificates', 'method', 'accept', 'data']
    assert result['http_request']['params']['accept'] == 'json'
    assert result['http_request']['params']['method'] == 'POST'
    urls = result['http_request']['params']['urls']
    assert urls == [TEST_URL+'/set_pin', TEST_ONION+'/set_pin']
    certs = result['http_request']['params']['root_certificates']
    assert certs == [TEST_CERT]

    data = result['http_request']['params']['data']
    assert data['ske'] == wally.hex_from_bytes(pubkey)  # ske echoed back

    cke = wally.hex_to_bytes(data['cke'])
    encrypted_data = wally.hex_to_bytes(data['encrypted_data'])
    hmac = wally.hex_to_bytes(data['hmac_encrypted_data'])

    # 3. This is where the app would call the URL returned with the data
    #    provided, and pass the response (encrypted server aes-key) to jade.
    #    Again, we use the pinserver class directly here.
    encrypted, hmac = server.call_with_payload(
        cke, encrypted_data, hmac, PINDb.set_pin)

    msg2 = jade.build_request(
                         'completeA3', 'handshake_complete',
                         {'encrypted_key': wally.hex_from_bytes(encrypted),
                          'hmac': wally.hex_from_bytes(hmac)})
    reply2 = jade.make_rpc_call(msg2)
    assert reply2['result'] is True

    # B: a test of 'get-pin' (ie. normal log-in)
    #    The hw test handler will verify that the fetched pin/key data
    #    matches that that was set in A: above.

    # We go through the same steps as above.

    # 1. initiate, get initial url
    msg = jade.build_request('debugB1', 'debug_handshake')
    reply = jade.make_rpc_call(msg)
    result = reply['result']
    assert list(result.keys()) == ['http_request'], result.keys()
    assert list(result['http_request'].keys()) == ['params', 'on-reply']
    assert result['http_request']['on-reply'] == 'handshake_init'
    assert list(result['http_request']['params'].keys()) == \
        ['urls', 'root_certificates', 'method', 'accept', 'data']
    assert result['http_request']['params']['accept'] == 'json'
    assert result['http_request']['params']['method'] == 'POST'
    urls = result['http_request']['params']['urls']
    assert urls == [TEST_URL+'/start_handshake', TEST_ONION+'/start_handshake']
    certs = result['http_request']['params']['root_certificates']
    assert certs == [TEST_CERT]

    # 2. pass pinserver ecdh key to jade
    # Note: PINServerECDH instances are ephemeral, so we create a new one
    #       here, as that is what would happen in pinserver proper.
    server = PINServerECDH()
    pubkey, sig = server.get_signed_public_key()

    msg = jade.build_request(
                        'initB2', 'handshake_init',
                        {'ske': wally.hex_from_bytes(pubkey),
                         'sig': wally.hex_from_bytes(sig)})
    reply = jade.make_rpc_call(msg)
    result = reply['result']

    assert list(result.keys()) == ['http_request'], result.keys()
    assert list(result['http_request'].keys()) == ['params', 'on-reply']
    assert result['http_request']['on-reply'] == 'handshake_complete'
    assert list(result['http_request']['params'].keys()) == \
        ['urls', 'root_certificates', 'method', 'accept', 'data']
    assert result['http_request']['params']['accept'] == 'json'
    assert result['http_request']['params']['method'] == 'POST'
    urls = result['http_request']['params']['urls']
    assert urls == [TEST_URL+'/get_pin', TEST_ONION+'/get_pin']
    certs = result['http_request']['params']['root_certificates']
    assert certs == [TEST_CERT]

    data = result['http_request']['params']['data']
    assert data['ske'] == wally.hex_from_bytes(pubkey)  # ske echoed back

    cke = wally.hex_to_bytes(data['cke'])
    encrypted_data = wally.hex_to_bytes(data['encrypted_data'])
    hmac = wally.hex_to_bytes(data['hmac_encrypted_data'])

    # 3. get encrypted server aes-key and pass to jade
    encrypted, hmac = server.call_with_payload(
        cke, encrypted_data, hmac, PINDb.get_aes_key)

    msg2 = jade.build_request(
                         'completeB3', 'handshake_complete',
                         {'encrypted_key': wally.hex_from_bytes(encrypted),
                          'hmac': wally.hex_from_bytes(hmac)})
    reply2 = jade.make_rpc_call(msg2)
    assert reply2['result'] is True


# Pinserver handshake test - set the hww back to the default/production
# authentication data - this should then fail with 'bad-sig' when we sign
# with the test pinserver details.
def test_handshake_bad_sig(jade):
    # 1. reset hww back to default pinserver details
    msg = jade.build_request('reset_pnsvr', 'update_pinserver',
                             {'reset_details': True, 'reset_certificate': True})
    reply = jade.make_rpc_call(msg)
    assert reply['result'] is True

    # 2. trigger the dedicated test case handler - check details are defaults
    msg = jade.build_request('badsig_start', 'debug_handshake')
    reply = jade.make_rpc_call(msg)
    result = reply['result']
    urls = result['http_request']['params']['urls']
    assert urls == [PINSERVER_DEFAULT_URL+'/start_handshake',
                    PINSERVER_DEFAULT_ONION+'/start_handshake']

    # By default no certificate is returned
    assert 'root_certificates' not in result['http_request']['params']

    # 3. This is where the app would call the URL returned, and pass the
    #    response (ecdh key) to jade.  We use the pinserver class directly.
    #    We expect this to fail as the pinserver signature will not match expected
    server = PINServerECDH()
    pubkey, sig = server.get_signed_public_key()

    msg = jade.build_request(
                        'badsig_init', 'handshake_init',
                        {'ske': wally.hex_from_bytes(pubkey),
                         'sig': wally.hex_from_bytes(sig)})
    reply = jade.make_rpc_call(msg)
    assert 'result' not in reply
    error = reply['error']
    assert error['code'] == JadeError.BAD_PARAMETERS
    assert error['message'] == 'Cannot initiate handshake - ske and/or sig invalid'


# Check/print memory stats
def check_mem_stats(startinfo, endinfo, check_frag=True, strict=True):
    # Memory stats to log/check
    breaches = []
    for field, limit in [('JADE_FREE_HEAP', 768),
                         ('JADE_FREE_DRAM', 768),
                         ('JADE_LARGEST_DRAM', 0 if check_frag else -1),
                         ('JADE_FREE_SPIRAM', 0),
                         ('JADE_LARGEST_SPIRAM', 0 if check_frag else -1)]:
        initial = int(startinfo[field])
        final = int(endinfo[field])
        diff = initial - final

        if limit >= 0 and diff > limit:
            logger.warning("{} - {} to {} ({}) BREACH".format(
                field, initial, final, diff))
            breaches.append(field)
        else:
            logger.info("{} - {} to {} ({})".format(
                field, initial, final, diff))

    if breaches:
        logger.error("Memory limit breaches: {}".format(breaches))
        assert not strict


# Helper to verify a signature - handles checking an Anti-Exfil signature
# contains the entropy that was passed in by the host.
def _verify_signature(jadeapi, network, msghash, path, host_entropy, signer_commitment, signature):
    # entropy/signer_commitment imply anti-exfil signature
    assert (host_entropy is None) == (signer_commitment is None)

    # Need to get the signer's pubkey
    xpub = jadeapi.get_xpub(network, path)
    hdkey = wally.bip32_key_from_base58(xpub)
    pubkey = wally.bip32_key_get_pub_key(hdkey)

    # If presented a 'recoverable' signature, recover the public key
    # and verify it matches that fetched from the hw above
    if len(signature) == wally.EC_SIGNATURE_RECOVERABLE_LEN:
        recovered_pubkey = wally.ec_sig_to_public_key(msghash, signature)
        assert recovered_pubkey == pubkey
        signature = signature[1:]  # Truncate leading byte for verification

    assert len(signature) == wally.EC_SIGNATURE_LEN
    if host_entropy:
        # Verify AE signature and that the host-entropy is included
        wally.ae_verify(pubkey, msghash, host_entropy, signer_commitment,
                        wally.EC_FLAG_ECDSA, signature)
    else:
        # Verify EC signature
        wally.ec_sig_verify(pubkey, msghash, wally.EC_FLAG_ECDSA, signature)


# Helper to verify a message signature - handles checking an Anti-Exfil signature
# contains the entropy that was passed in by the host.
def _check_msg_signature(jadeapi, testcase, actual):
    expected = testcase['expected_output']
    assert len(actual) == len(expected)

    inputdata = testcase['input']
    host_entropy = inputdata.get('ae_host_entropy')
    network = 'localtest'  # Network is irrelevant to sign-msg

    if host_entropy:
        # Anti-Exfil signer_commitment and signature
        assert tuple(expected) == actual, [actual[0].hex(), actual[1]]
        signer_commitment, signature = actual
    else:
        # Standard EC signature
        assert actual == expected, actual
        signer_commitment, signature = None, actual  # No signer_commitment for EC sig

    # Get the message hash
    msgbytes = inputdata['message'].encode('utf8')
    msghash = wally.format_bitcoin_message(msgbytes, wally.BITCOIN_MESSAGE_FLAG_HASH)

    rawsig = base64.b64decode(signature)  # un-base64 the returned signature

    # Verify the signature
    _verify_signature(jadeapi, network, msghash, inputdata['path'],
                      host_entropy, signer_commitment, rawsig)


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
            if commitments:
                wally.tx_set_output_asset(txn, i, commitments['asset_generator'])
                wally.tx_set_output_value(txn, i, commitments['value_commitment'])
    else:
        # BTC tx, straightforward
        txn = wally.tx_from_bytes(test_input['txn'], 0)

    # Iterate over the results verifying each signature
    for i, (expected, actual) in enumerate(zip(testcase['expected_output'], rslt)):
        if use_ae_signatures:
            # Anti-Exfil signer_commitment and signature (might not be low-r)
            assert tuple(expected) == actual, list(map(bytes.hex, actual))
            assert len(actual[1]) <= wally.EC_SIGNATURE_DER_MAX_LEN
            signer_commitment, signature = actual
        else:
            # Standard EC signature should be low-r
            assert actual == expected, actual.hex()
            assert len(actual) <= wally.EC_SIGNATURE_DER_MAX_LOW_R_LEN
            signer_commitment, signature = None, actual  # No signer_commitment for EC sig

        # Verify signature (if we signed this input)
        if len(signature):
            inputdata = test_input['inputs'][i]

            # Get the signature message hash (ie. the hash value that was signed)
            tx_flags = wally.WALLY_TX_FLAG_USE_WITNESS if inputdata['is_witness'] else 0
            if is_liquid:
                msghash = wally.tx_get_elements_signature_hash(
                    txn, i, inputdata['script'], inputdata.get('value_commitment'),
                    wally.WALLY_SIGHASH_ALL, tx_flags)
            else:
                if 'input_tx' in inputdata:
                    # Get satoshi amount from input tx if we have one
                    utxo_index = wally.tx_get_input_index(txn, i)
                    input_txn = wally.tx_from_bytes(inputdata['input_tx'], 0)
                    satoshi = wally.tx_get_output_satoshi(input_txn, utxo_index)
                else:
                    # If no input_tx, sats can be passed instead
                    # (Now only valid for single-input segwit tx)
                    assert inputdata['is_witness'] and len(test_input['inputs']) == 1
                    satoshi = inputdata['satoshi']

                msghash = wally.tx_get_btc_signature_hash(
                    txn, i, inputdata['script'], satoshi, wally.WALLY_SIGHASH_ALL, tx_flags)

            # Verify signature!
            rawsig = wally.ec_sig_from_der(signature[:-1])  # truncate sighash byte
            host_entropy = inputdata.get('ae_host_entropy') if use_ae_signatures else None
            _verify_signature(jadeapi, network, msghash, inputdata['path'],
                              host_entropy, signer_commitment, rawsig)


def run_api_tests(jadeapi, qemu=False, authuser=False):

    # On connection, a companion app should:
    # a) get the version info and check is compatible, needs update, etc.
    # b) if firmware ok, optionally send in some entropy for the rng
    # c) tell the jade to authenticate the user (eg. pin entry)
    #    - here we use 'set_mnemonic' instead to replace hw authentication
    rslt = jadeapi.get_version_info()
    assert len(rslt) == NUM_VALUES_VERINFO

    noise = os.urandom(64)
    rslt = jadeapi.add_entropy(bytes(noise))
    assert rslt is True

    if authuser:
        # Full user authentication with jade and pinserver (must be running)
        rslt = jadeapi.auth_user('testnet')
        assert rslt is True

    # Set mnemonic here instead of (or to override the result of) 'auth_user'
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    startinfo = jadeapi.get_version_info()
    assert len(startinfo) == NUM_VALUES_VERINFO
    has_psram = startinfo['JADE_FREE_SPIRAM'] > 0

    # Update pinserver details - just check the calls do not error
    # See test_handshake() above for more in-depth test of this functionality
    with open(PINSERVER_TEST_PUBKEY_FILE, 'rb') as f:
        pubkey = f.read()
    rslt = jadeapi.set_pinserver('testurl', 'testonion', pubkey, 'testcert')
    assert(rslt)
    rslt = jadeapi.reset_pinserver(True, True)
    assert(rslt)

    # Get (receive) green-address
    for network, subact, branch, ptr, recovxpub, csvblocks, expected in GET_GREENADDRESS_DATA:
        rslt = jadeapi.get_receive_address(network, subact, branch, ptr, recovery_xpub=recovxpub,
                                           csv_blocks=csvblocks)
        assert rslt == expected

    # Get xpubs
    for path, network, expected in GET_XPUB_DATA:
        rslt = jadeapi.get_xpub(network, path)
        assert rslt == expected

    # Sign message
    for msg_data in SIGN_MSG_TESTS:
        inputdata = msg_data['input']
        rslt = jadeapi.sign_message(inputdata['path'],
                                    inputdata['message'],
                                    inputdata.get('use_ae_signatures'),
                                    inputdata.get('ae_host_commitment'),
                                    inputdata.get('ae_host_entropy'))

        # Check returned signature
        _check_msg_signature(jadeapi, msg_data, rslt)

    # Sign Tx
    for txn_data in SIGN_TXN_TESTS:
        inputdata = txn_data['input']
        rslt = jadeapi.sign_tx(inputdata['network'],
                               inputdata['txn'],
                               inputdata['inputs'],
                               inputdata['change'],
                               inputdata.get('use_ae_signatures'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, txn_data, rslt)

    # Sign Tx failures
    for txn_data in SIGN_TXN_FAIL_CASES:
        try:
            inputdata = txn_data['input']
            rslt = jadeapi.sign_tx(inputdata['network'],
                                   inputdata['txn'],
                                   inputdata['inputs'],
                                   inputdata['change'],
                                   inputdata.get('use_ae_signatures'))
            assert False, "Expected exception from bad sign_tx test case"
        except JadeError as err:
            assert err.message == txn_data["expected_error"]

        for i in range(txn_data["extra_responses"]):
            logger.debug(jadeapi.jade.read_response())

    # Get Liquid master blinding key
    rslt = jadeapi.get_master_blinding_key()
    assert rslt == EXPECTED_MASTER_BLINDING_KEY

    # Get Liquid script blinding key
    rslt = jadeapi.get_blinding_key(TEST_SCRIPT)
    assert rslt == EXPECTED_BLINDING_KEY

    # Get Liquid shared nonce
    rslt = jadeapi.get_shared_nonce(TEST_SCRIPT, TEST_THEIR_PK)
    assert rslt == EXPECTED_SHARED_SECRET

    # Get Liquid shared nonce and public blinding key in one call
    rslt = jadeapi.get_shared_nonce(TEST_SCRIPT, TEST_THEIR_PK, include_pubkey=True)
    assert rslt['shared_nonce'] == EXPECTED_SHARED_SECRET
    assert rslt['blinding_key'] == EXPECTED_BLINDING_KEY

    # Get Liquid blinding factor
    rslt = jadeapi.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'ASSET')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['abf']

    # Get Liquid commitments without custom VBF
    rslt = jadeapi.get_commitments(TEST_REGTEST_BITCOIN,
                                   9000000,
                                   TEST_HASH_PREVOUTS,
                                   3)
    assert _dicts_eq(rslt, EXPECTED_LIQ_COMMITMENT_1)

    # Get Liquid commitments with custom VBF
    rslt = jadeapi.get_commitments(TEST_REGTEST_BITCOIN,
                                   9000000,
                                   TEST_HASH_PREVOUTS,
                                   0,
                                   EXPECTED_LIQ_COMMITMENT_2['vbf'])
    assert _dicts_eq(rslt, EXPECTED_LIQ_COMMITMENT_2)

    # This checks that we get the same blinders and commitments as we got
    # using a ledger.  See also test_data/txn_liquid_ledger_compare.json,
    # which is the same tx as ledger-signed liquid tx:
    # 4b4a27e482eff9dbaa52e7bada4cd7115c299c8e6ac8ebbd20e8d923ad2dad00
    # - and gets the same blinders and the same final signatures.

    # This is the hash-prevout for that transaction
    LEDGER_COMPARE_HASH_PREVOUT = h2b('7e78263a58236ffd160ee5a2c58c18b71637974\
aa95e1c72070b08208012144f')

    ledger_txs = list(_get_test_cases("liquid_txn_ledger_compare.json"))
    assert len(ledger_txs) == 1
    ledger_commitments = ledger_txs[0]['input']['trusted_commitments']
    assert len(ledger_commitments) == 3
    assert ledger_commitments[2] is None

    # First output commitments, no custom vbf
    rslt = jadeapi.get_commitments(ledger_commitments[0]['asset_id'],
                                   ledger_commitments[0]['value'],
                                   LEDGER_COMPARE_HASH_PREVOUT,
                                   0)
    del ledger_commitments[0]['blinding_key']
    assert _dicts_eq(rslt, ledger_commitments[0])

    # Second output commitments, including custom vbf
    rslt = jadeapi.get_commitments(ledger_commitments[1]['asset_id'],
                                   ledger_commitments[1]['value'],
                                   LEDGER_COMPARE_HASH_PREVOUT,
                                   1,
                                   ledger_commitments[1]['vbf'],)
    del ledger_commitments[1]['blinding_key']
    assert _dicts_eq(rslt, ledger_commitments[1])

    # Sign Liquid Tx
    for txn_data in SIGN_LIQUID_TXN_TESTS:
        inputdata = txn_data['input']
        rslt = jadeapi.sign_liquid_tx(inputdata['network'],
                                      inputdata['txn'],
                                      inputdata['inputs'],
                                      inputdata['trusted_commitments'],
                                      inputdata['change'],
                                      inputdata.get('use_ae_signatures'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, txn_data, rslt)

    # Generic multisig - check register multisig wallets
    for multisig_data in MULTI_REG_TESTS:
        inputdata = multisig_data['input']
        rslt = jadeapi.register_multisig(inputdata['network'],
                                         inputdata['multisig_name'],
                                         inputdata['descriptor']['variant'],
                                         inputdata['descriptor']['threshold'],
                                         inputdata['descriptor']['signers'])
        assert rslt is True

        # Check present and correct in 'get_registered_multisigs'
        registered_multisigs = jadeapi.get_registered_multisigs()
        multisig_desc = registered_multisigs.get(inputdata['multisig_name'])
        assert multisig_desc is not None
        assert multisig_desc['variant'] == inputdata['descriptor']['variant']
        assert multisig_desc['threshold'] == inputdata['descriptor']['threshold']
        assert multisig_desc['num_signers'] == len(inputdata['descriptor']['signers'])

        # This includes 'get receive address' tests
        for addr_test in multisig_data['address_tests']:
            rslt = jadeapi.get_receive_address(inputdata['network'],
                                               addr_test['paths'],
                                               multisig_name=inputdata['multisig_name'])
            assert rslt == addr_test['expected_address']

    # This test checks that the generic multisig wallets 'matches_ga', do...
    # ie. if I use the standard ga receive-address, I get the same result as
    # that using 'generic multisig' (as the co-signers are set-up to match green)
    matching_ga_msigs = _get_test_cases("multisig_reg_*matches_ga_*.json")
    for ga_msig in matching_ga_msigs:
        inputdata = ga_msig['input']
        signers = inputdata['descriptor']['signers']

        # Check this test looks good - ie. 2of2 or 2of3
        assert inputdata['descriptor']['threshold'] == 2
        assert len(signers) == 2 or len(signers) == 3
        user_signer = signers[1]  # signers[0] is ga-service

        # Handle subaccounts
        if len(user_signer['derivation']) == 1:
            subaccount = 0
            branch = user_signer['derivation'][0]
        elif len(user_signer['derivation']) == 3:
            assert user_signer['derivation'][0] == 2147483651  # 3'
            assert user_signer['derivation'][1] > 2147483648  # subaccount'
            subaccount = user_signer['derivation'][1] - 2147483648  # unharden
            branch = user_signer['derivation'][2]
        else:
            assert False, "Unexpected derivation for ga-multisig wallet"

        user_xpub = jadeapi.get_xpub(inputdata['network'], user_signer['derivation'])
        assert user_xpub == user_signer['xpub']   # checks our xpub entry
        recovery_xpub = signers[2]['xpub'] if len(signers) == 3 else None

        # Check receive addresses fetched using normal green call matches the
        # expected results (which are tested as a generic multisig address above)
        for addr_test in ga_msig['address_tests']:
            ptr = addr_test['paths'][0][0]
            # check all signers have same single-entry path (ie. 'ptr')
            assert(all(p == [ptr] for p in addr_test['paths']))
            rslt = jadeapi.get_receive_address(inputdata['network'], subaccount, branch, ptr,
                                               recovery_xpub=recovery_xpub)
            assert rslt == addr_test['expected_address']

    # Sign txns using generic multisig registration
    ga_2of2_multisig_data = list(_get_test_cases("multisig_reg_matches_ga_2of2.json"))
    assert len(ga_2of2_multisig_data) == 1
    ga_2of2_multisig_name = ga_2of2_multisig_data[0]['input']['multisig_name']

    MULTISIG_SIGN_TXS = ['txn_2of2_change.json', 'txn_segwit_multi_input.json']
    ga_2of2_multisig_txns = (list(_get_test_cases(testcase))[0] for testcase in MULTISIG_SIGN_TXS)
    for ga_msig in ga_2of2_multisig_txns:
        inputdata = ga_msig['input']

        # Doctor the change paths to include the registered multisig name, but not
        # the multisig xpub root (ie. to only contain the final 'ptr' part)
        # (as the subact/branch is part of the multisig registration)
        for change in inputdata.get('change'):
            if change is not None:
                path = change.pop('path')
                change['paths'] = [path[-1:]] * 2
                change['multisig_name'] = ga_2of2_multisig_name

        rslt = jadeapi.sign_tx(inputdata['network'],
                               inputdata['txn'],
                               inputdata.get('inputs'),
                               inputdata.get('change'),
                               inputdata.get('use_ae_signatures'),
                               )

        # Check returned signatures
        _check_tx_signatures(jadeapi, ga_msig, rslt)

    # Short sanity-test of 12-word mnemonic
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC_12)
    assert rslt is True
    rslt = jadeapi.get_xpub('mainnet', [1, 12])
    assert rslt == 'xpub6BETMaQnyXi1gqFdL5FX8A3YEtRCEvBPijmr7EL42rGeEc6pvjYv25\
ZoxpDgc3UZwmpCgfdCkNmcSQa2tjnZLPohvRFECZP9P1boFKdJ5Sx'
    rslt = jadeapi.get_receive_address('mainnet', 1, 1, 231)
    assert rslt == '38SBTKLCNKVvQh1jPpbkAbXa3gtRJEh9Ud'

    # Sign single sig
    # Single sig requires a different seed for the tests
    rslt = jadeapi.set_seed(bytes.fromhex(TEST_SEED_SINGLE_SIG))
    assert rslt is True

    # Get receive address
    for network, variant, path, expected in GET_SINGLE_SIG_ADDR_DATA:
        rslt = jadeapi.get_receive_address(network, path, variant=variant)
        assert rslt == expected

    for txn_data in SIGN_SINGLE_SIG_TESTS:
        inputdata = txn_data['input']
        rslt = jadeapi.sign_tx(inputdata['network'],
                               inputdata['txn'],
                               inputdata['inputs'],
                               inputdata['change'],
                               inputdata.get('use_ae_signatures'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, txn_data, rslt)

    for txn_data in SIGN_SINGLE_SIG_LIQUID_TESTS:
        inputdata = txn_data['input']
        rslt = jadeapi.sign_liquid_tx(inputdata['network'],
                                      inputdata['txn'],
                                      inputdata['inputs'],
                                      inputdata['trusted_commitments'],
                                      inputdata['change'],
                                      inputdata.get('use_ae_signatures'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, txn_data, rslt)

    # Register multisig wallets again - this checks that a second user from the multisig
    # gets the same receive-address.  ie. in the tests 'multisig_reg_ss' the 'single sig'
    # signer is also in the multisig, so we can check it from this wallet also.
    for multisig_data in MULTI_REG_SS_TESTS:
        # Test trying to access the multisig description registered under the
        # main test mnemonic fails (as must be registered by accessing wallet)
        inputdata = multisig_data['input']
        try:
            for addr_test in multisig_data['address_tests']:
                rslt = jadeapi.get_receive_address(inputdata['network'],
                                                   addr_test['paths'],
                                                   multisig_name=inputdata['multisig_name'])
                assert False, "Accessing other wallet multisig should fail"
        except JadeError as e:
            assert e.code == JadeError.BAD_PARAMETERS
            assert e.message == "Cannot de-serialise multisig wallet data"

        # If we register the same multisig description to this wallet, it should produce
        # the same addresses as it did previously (for the other signatory)
        rslt = jadeapi.register_multisig(inputdata['network'],
                                         inputdata['multisig_name'],
                                         inputdata['descriptor']['variant'],
                                         inputdata['descriptor']['threshold'],
                                         inputdata['descriptor']['signers'])
        assert rslt is True

        # Check present and correct in 'get_registered_multisigs'
        registered_multisigs = jadeapi.get_registered_multisigs()
        multisig_desc = registered_multisigs.get(inputdata['multisig_name'])
        assert multisig_desc is not None
        assert multisig_desc['variant'] == inputdata['descriptor']['variant']
        assert multisig_desc['threshold'] == inputdata['descriptor']['threshold']
        assert multisig_desc['num_signers'] == len(inputdata['descriptor']['signers'])

        # This includes 'get receive address' tests
        for addr_test in multisig_data['address_tests']:
            rslt = jadeapi.get_receive_address(inputdata['network'],
                                               addr_test['paths'],
                                               multisig_name=inputdata['multisig_name'])
            assert rslt == addr_test['expected_address']

    # restore the mnemonic
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    time.sleep(1)  # Lets idle tasks clean up
    endinfo = jadeapi.get_version_info()
    check_mem_stats(startinfo, endinfo)


# Run tests using passed interface
def run_interface_tests(jadeapi,
                        qemu=False,
                        authuser=False,
                        smoke=True,
                        negative=True,
                        test_overflow_input=False):
    assert jadeapi is not None

    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    startinfo = jadeapi.get_version_info()
    assert len(startinfo) == NUM_VALUES_VERINFO
    has_psram = startinfo['JADE_FREE_SPIRAM'] > 0

    # Smoke tests
    if smoke:
        logger.info("Smoke tests")
        rslt = jadeapi.run_remote_selfcheck()
        assert rslt is True

        # This test passes on qemu locally but seems broken on CI
        # Skip for now.
        if not qemu:
            test_handshake(jadeapi.jade)
            test_handshake_bad_sig(jadeapi.jade)

        # Test mnemonic-with-passphrase
        test_passphrase(jadeapi.jade)

    # Too much input test - sends a lot of data so only
    # run if requested (eg. ble would take a long time)
    # Note also does not work on qemu - skip for now.
    if test_overflow_input and not qemu:
        logger.info("Buffer overflow test - PSRAM: {}".format(has_psram))
        test_too_much_input(jadeapi.jade, has_psram)

    # Negative tests
    if negative:
        logger.info("Negative tests")
        test_bad_message(jadeapi.jade)
        test_very_bad_message(jadeapi.jade)
        test_split_message(jadeapi.jade)
        test_concatenated_messages(jadeapi.jade)
        test_unknown_method(jadeapi.jade)
        test_unexpected_method(jadeapi.jade)
        test_bad_params(jadeapi.jade)
        test_bad_params_liquid(jadeapi.jade)

    time.sleep(1)  # Lets idle tasks clean up
    endinfo = jadeapi.get_version_info()
    check_mem_stats(startinfo, endinfo)


# Run all selected tests over a passed JadeAPI instance.
def run_jade_tests(jadeapi, args, extended_tests):
    logger.info("Running selected Jade tests over passed connection")

    # Low-level JadeInterface tests
    if not args.skiplow:
        run_interface_tests(jadeapi, qemu=args.qemu, authuser=args.authuser,
                            test_overflow_input=extended_tests)

    # High-level JadeAPI tests
    if not args.skiphigh:
        run_api_tests(jadeapi, qemu=args.qemu, authuser=args.authuser)


# This test should be passed 2 different connections to the same jade hw
# - both serial and ble connected at the same time.
# Test that is we auth over one, we can't do sensitive calls over the other.
def mixed_sources_test(jade1, jade2):

    # Example of a 'sensitve' call
    path, network, expected = GET_XPUB_DATA[0]

    # jade1 can unlock jade, then get xpub fine
    jade1.set_mnemonic(TEST_MNEMONIC)
    rslt = jade1.get_xpub(network, path)
    assert rslt == expected

    # jade2 gets an error about jade being locked (for them)
    try:
        rslt = jade2.get_xpub(network, path)
        assert False, "Excepted exception from mixed sources test"
    except JadeError as err:
        assert err.code == JadeError.HW_LOCKED

    # jade1 is still fine
    rslt = jade1.get_xpub(network, path)
    assert rslt == expected

    # Now jade2 unlocks jade - they can get xpub but jade1 now cannot
    jade2.set_mnemonic(TEST_MNEMONIC)
    rslt = jade2.get_xpub(network, path)
    assert rslt == expected

    try:
        rslt = jade1.get_xpub(network, path)
        assert False, "Excepted exception from mixed sources test"
    except JadeError as err:
        assert err.code == JadeError.HW_LOCKED

    # jade2 is still fine
    rslt = jade2.get_xpub(network, path)
    assert rslt == expected


# Run all selected tests over all selected backends (serial/ble)
def run_all_jade_tests(info, args):
    logger.info("Running Jade tests over selected backend interfaces")

    # 1. Test over serial connection
    if not args.skipserial:
        logger.info("Testing Serial ({})".format(args.serialport))
        with JadeAPI.create_serial(args.serialport,
                                   timeout=SRTIMEOUT) as jade:
            run_jade_tests(jade, args, True)  # include extended tests

    # 2. Test over BLE connection
    if not args.skipble:
        if info['JADE_CONFIG'] == 'BLE':
            bleid = info['EFUSEMAC'][6:]
            logger.info("Testing BLE ({})".format(bleid))
            with JadeAPI.create_ble(serial_number=bleid) as jade:
                run_jade_tests(jade, args, False)  # skip long tests over ble

                # 3. If also testing over serial, run the 'mixed sources' tests
                if not args.skipserial:
                    logger.info("Running 'mixed sources' Tests")
                    with JadeAPI.create_serial(args.serialport,
                                               timeout=SRTIMEOUT) as jadeserial:
                        mixed_sources_test(jadeserial, jade)
        else:
            msg = "Skipping BLE tests - not enabled on the hardware"
            logger.warning(msg)


# Connect to Jade by serial or BLE and get the info block
def get_jade_info(args):
    if not args.skipserial:
        logger.info("Getting info via Serial ({})".format(args.serialport))
        with JadeAPI.create_serial(device=args.serialport,
                                   timeout=SRTIMEOUT) as jade:
            return jade.get_version_info()

    if not args.skipble:
        bleid = args.bleid
        logger.info("Getting info via BLE ({})".format(id or '<any>'))
        with JadeAPI.create_ble(serial_number=bleid) as jade:
            return jade.get_version_info()


def test_ble_connection_fails(info, args):
    if not args.skipble:
        if info['JADE_CONFIG'] == 'BLE':
            bleid = info['EFUSEMAC'][6:]
            logger.info("Testing BLE connection fails or times-out")
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
                    assert False, "test_ble_connection_fails() connected!"
                except KeyboardInterrupt as e:
                    logger.info("BLE connection timed-out: {}".format(e))
                except Exception as e:
                    logger.info("BLE connection failed with: {}".format(e))
                finally:
                    timer.cancel()
                    jade.disconnect()
        else:
            msg = "Skipping BLE tests - not enabled on the hardware"
            logger.warning(msg)


def check_stuck():
    # FIXME: serial/ble reads/writes should timeout before this does
    timeout = 15  # minutes
    time.sleep(60 * timeout)
    err_str = "tests got caught running longer than {} minutes, terminating"
    logger.error(err_str.format(timeout))
    logger.handlers[0].flush()
    os._exit(1)


def start_agent(passkey_file):
    logger.info('Starting bt-agent with passkey file: {}'.format(passkey_file))
    command = ['/usr/bin/bt-agent', '-c', 'DisplayYesNo', '-p', passkey_file]
    btagent = subprocess.Popen(command,
                               shell=False,
                               stdout=subprocess.DEVNULL)
    logger.info('Started bt-agent with process id: {}'.format(btagent.pid))
    return btagent


def kill_agent(btagent):
    command = 'kill -HUP {}'.format(btagent.pid)
    subprocess.run(command,
                   shell=True,
                   stdout=subprocess.DEVNULL)
    logger.info('Killed bt-agent {}'.format(btagent.pid))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    sergrp = parser.add_mutually_exclusive_group()
    sergrp.add_argument("--skipserial",
                        action="store_true",
                        dest="skipserial",
                        help="Skip testing over serial connection",
                        default=False)
    sergrp.add_argument("--serialport",
                        action="store",
                        dest="serialport",
                        help="Serial port or device",
                        default=DEFAULT_SERIAL_DEVICE)

    blegrp = parser.add_mutually_exclusive_group()
    blegrp.add_argument("--skipble",
                        action="store_true",
                        dest="skipble",
                        help="Skip testing over BLE connection",
                        default=False)
    blegrp.add_argument("--bleid",
                        action="store",
                        dest="bleid",
                        help="BLE device serial number or id",
                        default=None)

    blegrp = parser.add_mutually_exclusive_group()
    blegrp.add_argument("--skiplow",
                        action="store_true",
                        dest="skiplow",
                        help="Skip low-level JadeInterface (negative) tests",
                        default=False)
    blegrp.add_argument("--skiphigh",
                        action="store_true",
                        dest="skiphigh",
                        help="Skip high-level JadeAPI (happy-path) tests",
                        default=False)

    agtgrp = parser.add_mutually_exclusive_group()
    agtgrp.add_argument("--noagent",
                        action="store_true",
                        dest="noagent",
                        help="Do not run the BLE passkey agent",
                        default=False)
    agtgrp.add_argument("--agentkeyfile",
                        action="store",
                        dest="agentkeyfile",
                        help="Use the specified BLE passkey agent key file",
                        default=BLE_TEST_PASSKEYFILE)

    parser.add_argument("--authuser",
                        action="store_true",
                        dest="authuser",
                        help="Full user authentication with Jade & pinserver",
                        default=False)
    parser.add_argument("--qemu",
                        action="store_true",
                        dest="qemu",
                        help="Skip tests which appear problematic on qemu hw emulator",
                        default=False)
    parser.add_argument("--log",
                        action="store",
                        dest="loglevel",
                        help="Jade logging level",
                        choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"],
                        default="INFO")
    args = parser.parse_args()
    jadehandler.setLevel(getattr(logging, args.loglevel))
    logger.debug('args: {}'.format(args))
    manage_agents = args.agentkeyfile and not args.skipble and not args.noagent

    if args.skipserial and args.skipble:
        logging.error("Can only skip one of Serial or BLE tests, not both!")
        os.exit(1)

    if args.bleid and not args.skipserial:
        logging.error("Can only supply ble-id when skipping serial tests")
        os.exit(1)

    # Run the thread that forces exit if we're too long running
    t = threading.Thread(target=check_stuck, daemon=True)
    t.start()

    # If ble, start the agent to supply the required passkey for authentication
    # and encryption - don't bother if not.
    # Note: passkey in the agent passkey file must match the fixed test passkey
    #       in jade source if we want the connection to succeed.
    btagent = None
    if manage_agents:
        btagent = start_agent(args.agentkeyfile)

    try:
        info = get_jade_info(args)
        if info:
            # Tests of low-level interface and negative tests
            run_all_jade_tests(info, args)

            # FIXME: appears to work (locally) on esp4.1 branch
            # Can only work if only one test running on the box
            # otherwise bt-agents interfere
            # if manage_agents:
            #    # Extra test for bad BLE passkey - should fail or time-out
            #    stop_all_agents()
            #    if btagent:
            #        kill_agent(btagent)
            #    logging.info("Testing BLE fails with incorrect passkey")
            #    btgent = start_agent(BLE_TEST_BADKEYFILE)
            #    test_ble_connection_fails(info, args)
        else:
            assert False, "Can't connect to Jade over serial or BLE"
    finally:
        if btagent:
            kill_agent(btagent)
