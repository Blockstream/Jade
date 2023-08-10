import os
import time
import glob
import cbor2 as cbor
import copy
import json
import base64
import random
import logging
import argparse
import subprocess
import threading
import _thread

from pinserver.server import PINServerECDH
from pinserver.pindb import PINDb
import wallycore as wally
from jadepy.jade import JadeAPI, JadeError

# Enable jade logging
jadehandler = logging.StreamHandler()

logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

device_logger = logging.getLogger('jadepy.jade-device')
device_logger.setLevel(logging.DEBUG)
device_logger.addHandler(jadehandler)


def h2b(hexdata):
    if hexdata is None:
        return None
    elif isinstance(hexdata, list):
        return list(map(h2b, hexdata))
    elif isinstance(hexdata, dict):
        return {k: h2b(v) for k, v in hexdata.items()}
    else:
        return bytes.fromhex(hexdata)


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
            additional_info = testcase['input']['additional_info']
            for summary_item in additional_info['wallet_input_summary']:
                summary_item['asset_id'] = h2b(summary_item['asset_id'])
            for summary_item in additional_info['wallet_output_summary']:
                summary_item['asset_id'] = h2b(summary_item['asset_id'])

        if 'expected_output' in testcase:
            testcase['expected_output'] = h2b(testcase['expected_output'])

    elif 'psbt' in testcase['input']:
        # sign-psbt data
        testcase['input']['psbt'] = base64.b64decode(testcase['input']['psbt'])
        testcase['expected_output']['psbt'] = base64.b64decode(testcase['expected_output']['psbt'])

        if 'txn' in testcase['expected_output']:
            testcase['expected_output']['txn'] = h2b(testcase['expected_output']['txn'])

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
    logger.info('Reading json file: {}'.format(filename))
    with open(filename, 'r') as json_file:
        return json.load(json_file)


# Helper to read json test files into a list
def _get_test_cases(pattern):
    return (_h2b_test_case(_read_json_file(f)) for f in glob.glob("./test_data/" + pattern))


BLE_TEST_PASSKEYFILE = "ble_test_passkey.txt"
BLE_TEST_BADKEYFILE = "ble_test_badkey.txt"

# The default serial read timeout
DEFAULT_SERIAL_TIMEOUT = 120

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

TEST_MNEMONIC_PREFIXES = 'fish inne face gin orc perm usef meth fen kidn chuc \
part fav suns draw limb scie cran ova let slot invi sadn bana'

# 'can' and 'net' are ambiguous prefixes, but are an exact match to words in
# the bip39-wordlist, so should be recognised/allowed.
TEST_MNEMONIC_PREFIXES_EXACT_MATCH = 'recy wear club hurr indu floa cust gua \
ae plan scan carr elec reco acco stoc insp net ups can opt brie guid priv'

# One word (met) prefix is not unambiguous: met => metal, method
TEST_MNEMONIC_PREFIXES_AMBIGUOUS = 'fish inne face gin orc perm usef met fen \
kidn chuc part fav suns draw limb scie cran ova let slot invi sadn bana'

# Seedsigner styles for our test mnemonic
TEST_MNEMONIC_SEEDSIGNER = '0701093106520784124813051919112106800979032412840\
67217400531103815430402126110281632094415190145'
TEST_MNEMONIC_SEEDSIGNER_COMPACT = b'W\xae\x8dF1\t\xc1F{\xfcaU\x0fL\xa2PEA\xb3\
\x10\x9c\x0e\xc0\xe6Jv\xc0L\xc0\xec/x'

# bcur bip39 style for our test mnemonic
TEST_MNEMONIC_BCUR_BIP39_LOWER = 'ur:crypto-bip39/oeadlkiyjkisinihjzieihiojpjl\
kpjoihihjpjlieihihhskthsjeihiejzjliajeiojkhskpjkhsioihieiahsjkisihiojzhsjpihie\
kthskoihieiajpihktihiyjzhsjnihihiojzjlkoihaoidihjtrkkndede'
TEST_MNEMONIC_BCUR_BIP39_UPPER = 'UR:CRYPTO-BIP39/OEADLKIYJKISINIHJZIEIHIOJPJL\
KPJOIHIHJPJLIEIHIHHSKTHSJEIHIEJZJLIAJEIOJKHSKPJKHSIOIHIEIAHSJKISIHIOJZHSJPIHIE\
KTHSKOIHIEIAJPIHKTIHIYJZHSJNIHIHIOJZJLKOIHAOIDIHJTRKKNDEDE'

TEST_MNEMONIC_BCUR_BIP39_STRING = 'shield group erode awake lock sausage \
cash glare wave crew flame glove'

TEST_MNEMONIC_12 = 'retire verb human ecology best member fiction measure \
demand stereo wedding olive'

TEST_MNEMONIC_12_IDENTITY = 'alcohol woman abuse must during monitor noble \
actual mixed trade anger aisle'

# Seedsigner's own test vectors
# See: https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md
SEEDSIGNER_MNEMONIC_TEST_VECTORS = [
  # 24-word
  ('attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony \
ranch winter theme error hybrid van cereal salon goddess expire',
   '0115132511540127119007710415074212891906200808700266134314202016179206140896192903001524080\
10643',
   b'\x0et\xb6A\x07\xf9L\xc0\xcc\xfa\xe6\xa1=\xcb\xec6b\x15O\xecg\xe0\xe0\t\x99\xc0x\x92Y}\x19\n'),
  ('atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element \
afraid meadow quick medal plate wisdom swap noble shallow',
   '0114165509641888007311191572188701560610025619321225144305730036110114051106132920181754119\
71576',
   b"\x0eY\xdd\xe2v\x00\x93\x17\xf1'_\x13\x89\x88\x80x\xc9\x93h\xd1\xe8$\x89\xb5\xf6)S\x1f\xc5\
\xb6\xa5n"),
  ('sound federal bonus bleak light raise false engage round stock update render quote truck \
quality fringe palace foot recipe labor glow tortoise potato still',
   '1662067502030188103614170658059415071712190814561408186514010744127307271437099407981836135\
01710',
   b'\xcf\xca\x8ce\x8b\xc8\x19bT\x92R\xbcz\xc3\xba[\x0b\x01\xd2k\xca\xe8\x9f+^\xce\xbe&=\xcb*6'),
  # 12-word
  ('forum undo fragile fade shy sign arrest garment culture tube off merit',
   '073318950739065415961602009907670428187212261116',
   b'[\xbd\x9dq\xa8\xecy\x90\x83\x1a\xff5\x9dBeE'),
  ('good battle boil exact add seed angle hurry success glad carbon whisper',
   '080301540200062600251559007008931730078802752004',
   b"dbhd' 3\x85\xc23}\xd8LP\x89\xfd"),
  ('approve fruit lens brass ring actual stool coin doll boss strong rate',
   '008607501025021714880023171503630517020917211425',
   b'\n\xcb\xba\x00\x8d\x9b\xa0\x05\xf5\x99k@\xa3G\\\xd9'),
  # Potentially Problematic
  ('dignity utility vacant shiver thought canoe feel multiply item youth actor coyote',
   '049619221923158517990268067811630950204300210397',
   b'>\x1e\x0b\xc1\xe3\x1e\x0eC\x154\x8bv\xdf\xec\n\x98'),
  ('corn voice scrap arrow original diamond trial property benefit choose junk lock',
   '038719631547010112530489185713790169032209701051',
   b'0~\xaf\x05\x86Y\xcazz\rc\x15%\t\xe5A'),
  ('vocal tray giggle tool duck letter category pattern train magnet excite swamp',
   '196218530783182905421028028912901848107106301753',
   b'\xf5\\\xf5\x87\xf2T=\x01\t\r\n\xe7\x10\xbd;m'),
]

# Test cases generated with: https://github.com/ethankosakovsky/bip85
GET_BIP85_BIP39_DATA = [
    (12, 0, "elephant this puppy lucky fatigue skate aerobic emotion peanut outer clinic casino"),
    (12, 12, "prevent marriage menu outside total tone prison few sword coffee print salad"),
    (12, 100, "lottery divert goat drink tackle picture youth text stem marriage call tip"),
    (12, 65535, "curtain angle fatigue siren involve bleak detail frame name spare size cycle"),

    (24, 0,
     "certain act palace ball plug they divide fold climb hand tuition inside choose sponsor grass "
     "scheme choose split top twenty always vendor fit thank"),
    (24, 24,
     "flip meat face wood hammer crack fat topple admit canvas bid capital leopard angry fan gate "
     "domain exile patient recipe nut honey resist inner"),
    (24, 1024,
     "phone goat wheel unique local maximum sand reflect scissors one have spin weasel dignity "
     "antenna acid pulp increase fitness typical bacon strike spy festival"),
    (24, 65535,
     "humble museum grab fitness wrap window front job quarter update rich grape gap daring blame "
     "cricket traffic sad trade easily genius boost lumber rhythm")
]

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

GET_GREENADDRESS_DATA = [('localtest', 0, 1, 345, None, 0, None,
                          '2MyMy6Ey7a5dmWJW1D9M7RFwjmXD1ECrgy4'),
                         ('testnet', 0, 1, 568, None, 51840, None,
                         '2MxbBuvnRvgL3uTDtTkufPTdzuwuXE9HCNj'),
                         ('mainnet', 3, 1, 88, '', 0, None,
                         '36kTtrBFR5NQmzBxAuNWcmLk22WsuhRq2S'),
                         ('mainnet', 0, 1, 568, 'xpub6BYx1MizD2XPpY6EuF5Pso8cG\
5fVHJEWniziGqXcrrcqH96MUiPcuNQkfKSnGx9tCvBJBZx35fiZE3zBbVkZqH89TU4W6HkyE9fSUx9\
QHNX', 0, None, '338M4PG24m1gZggrzQV1s9vr3dZZ31kLsU'),
                         ('localtest-liquid', 6, 1, 345, None, 65535, None,
                          'Azpx2UGRpzEQ6pt6yCbPYGnjqNaTtxN2ZdLmMMjWMVvJdzd5uD9\
cysaRc4Es5auve68RAwijQqReG3AT'),
                         ('testnet-liquid', 3, 1, 244, None, 65535, None,
                          'vjU6NdME2viTa8BzBA6qNG5jQKLfGfLvC93f4fRwZ9SR4pE7KBW\
QNbGUi2bodfxiMACFDombViiC5Vej'),
                         ('liquid', 10, 1, 122, None, 65535, None,
                          'VJLGotGqjthW3NY7JFZ7EaJZo8rnuRi23waPVY7FwJTYxtFNrNL\
y6CC4VEQoKRmd5VkL2mmuo64LfZNy'),

                         # Jade can generate non-confidential addresses also
                         ('testnet-liquid', 0, 1, 9, None, 65535, None,
                          'vjTzk5t4D8J3j73rt2QWsD9UMSs28KcNnYSGovgGBKcpfHpihSz\
5bsMmUNAkdohYRHXPztnqgZqaLgEk'),
                         ('testnet-liquid', 0, 1, 9, None, 65535, True,
                          'vjTzk5t4D8J3j73rt2QWsD9UMSs28KcNnYSGovgGBKcpfHpihSz\
5bsMmUNAkdohYRHXPztnqgZqaLgEk'),
                         ('testnet-liquid', 0, 1, 9, None, 65535, False,
                          '8z6YuTaMWRf4UeqAGKmQ64Bi4wPWtw7pqm')]

GET_SINGLE_SIG_ADDR_DATA = [  # The below were generated on core
                            ('localtest', 'sh(wpkh(k))', None,
                             [2147483648, 2147483648, 2147483657],
                             '2N8Yn3oXF7Pg38yBpuvoheDS7981vW4vy5b'),
                            ('localtest', 'wpkh(k)', None,
                             [2147483648, 2147483648, 2147483658],
                             'bcrt1qkrkcltr7kx5s5alsvnpvkcfunlrjtwx942zmn4'),
                            ('localtest', 'pkh(k)', None,
                             [2147483648, 2147483648, 2147483659],
                             'mwJDHFp93fuHZysBwU7RTiFXrJZXXcPuUc'),
                            # And these on elements ...
                            ('localtest-liquid', 'sh(wpkh(k))', None,
                             [2147483648, 2147483648, 2147483649],
                             'AzpnFQq17AnWm4gvL2oHLRucFawmq8VWFyaxfPX3EgrihEdw\
DXWmb1QmA7QrRu5RCy3wDtSe8h9WxKbQ'),
                            ('localtest-liquid', 'wpkh(k)', None,
                             [2147483648, 2147483648, 2147483650],
                             'el1qqwud2rtjxwgfxc9wrey504mtjqujrmzsc442zway65gk\
uj2f0mm4xfv8h3sqfz223jxjrj307zyqln2dywxmsvpvs9x2tvufj'),
                            ('localtest-liquid', 'pkh(k)', None,
                             [2147483648, 2147483648, 2147483651],
                             'CTEuAWMSL94hM2PbTzoe8TGLjyVkkSgdPFas7eUMouiGk5Q2\
SfzadGnGduPwvoVK1ZpthykJup8A8Eh2'),

                            # The below are 'speculative' ...
                            ('mainnet', 'sh(wpkh(k))', None,
                             [2147483648, 2147483648, 2147483657],
                             '3GzZz4bDVwAgwBZHEoBq2GSqvmokj9e4Jx'),
                            ('mainnet', 'wpkh(k)', None,
                             [2147483648, 2147483648, 2147483657],
                             'bc1qpky3r9yuz5gguvuqkrf2dfqtqgutr9evgnjmq6'),
                            ('mainnet', 'pkh(k)', None,
                             [2147483648, 2147483648, 2147483657],
                             '12EZzC9ck31rxaFYKbGwVj1gYXsUwfHuWj'),

                            ('testnet', 'sh(wpkh(k))', None,
                             [2147483648, 2147483648, 2147483657],
                             '2N8Yn3oXF7Pg38yBpuvoheDS7981vW4vy5b'),
                            ('testnet', 'wpkh(k)', None,
                             [2147483648, 2147483648, 2147483657],
                             'tb1qpky3r9yuz5gguvuqkrf2dfqtqgutr9evz4fgmf'),
                            ('testnet', 'pkh(k)', None,
                             [2147483648, 2147483648, 2147483657],
                             'mgkXHFEbZ4T7jgjA3AFKKeE1QXUBrX7qQC'),

                            ('liquid', 'sh(wpkh(k))', None,
                             [2147483648, 2147483648, 2147483657],
                             'VJLGcUjN2q6HHuNUAQJ2LEASQnr5LkD2DgDwT2vcyQjKhA3B\
5a2VAgp94Gj5rSXYiD6eHmGJmVSHY5xG'),
                            ('testnet-liquid', 'wpkh(k)', None,
                             [2147483648, 2147483648, 2147483657],
                             'tlq1qq28n8pj790vsyd6t5lr6n0puhrp7hd8wvcgrlm8knxm\
684lxq6pzjrvfzx2fc9gs3cecpvxj56jqkq3ckxtjc88gqxa6j2cv7'),

                            # Jade can generate non-confidential addresses also
                            ('localtest-liquid', 'pkh(k)', None,
                             [2147483648, 2147483648, 2147483657],
                             'CTEjtdpkvj7mrGtgMTrmDfSnH9DdN9Rzi2tzsxsFNujSU8qh\
YzNnQaWx24j5hX8iWcaZgTZJ6Y3sedLi'),
                            ('localtest-liquid', 'pkh(k)', True,
                             [2147483648, 2147483648, 2147483657],
                             'CTEjtdpkvj7mrGtgMTrmDfSnH9DdN9Rzi2tzsxsFNujSU8qh\
YzNnQaWx24j5hX8iWcaZgTZJ6Y3sedLi'),
                            ('localtest-liquid', 'pkh(k)', False,
                             [2147483648, 2147483648, 2147483657],
                             '2dafKNiCKbRum9S1u5BYqTByZT5R9zSqcWy')]

# Hold test data in separate files as can be large
QR_SCAN_TESTS = "qr_*.json"
MULTI_REG_TESTS = "multisig_reg_*.json"
MULTI_REG_SS_TESTS = "multisig_reg_ss_*.json"
MULTI_REG_FILE_TESTS = "multisig_file_*.json"
MULTI_REG_BAD_FILE_TESTS = "multisig_bad_file_*.json"
DESCRIPTOR_REG_SS_TESTS = "descriptor_ss_*.json"
SIGN_MSG_TESTS = "msg_*.json"
SIGN_MSG_FILE_TESTS = "msgfile_*.json"
SIGN_IDENTITY_TESTS = "identity_*.json"
SIGN_TXN_TESTS = "txn_*.json"
SIGN_TXN_FAIL_CASES = "badtxn_*.json"
SIGN_LIQUID_TXN_TESTS = "liquid_txn_*.json"
SIGN_TXN_SINGLE_SIG_TESTS = "singlesig_txn*.json"
SIGN_LIQUID_TXN_SINGLE_SIG_TESTS = "singlesig_liquid_txn*.json"
SIGN_PSBT_TESTS = "psbt_tm_*.json"
SIGN_PSBT_SS_TESTS = "psbt_ss_*.json"

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

SIGN_IDENTITY_DATA = [
    # challenge, identity, index, curve, slip13 pubkey, signature prefixed 0x00, slip17 pubkey
    # First test case copied from:
    # https://github.com/trezor/trezor-firmware/blob/a3c79bf4f7393386d23fe92210c7bce4d1049280
    # /tests/device_tests/misc/test_msg_signidentity.py#L75
    # NOTE: slight differnece as we return the *uncompressed* pubkey
    # THIS IS THE ONE TRUE TEST (except the ecdh pubkey, which is unverified)
    ('cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2',
     'ssh://satoshi@bitcoin.org', 47, 'nist256p1',
     '0473f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4d56471\
0ca0bf84b81c6850e916cb94ae9c397b550589da476ace7aee39ebcb37',
     '005122cebabb852cdd32103b602662afa88e54c0c0c1b38d7099c64dcd49efe908288114\
e66ed2d8c82f23a70b769a4db723173ec53840c08aafb840d3f09a18d3',
     '04248befa95e9dbcf0a2ef7cf6957651ee25a168355590c4c84a6a8601758ca230d397bc\
ba67b4676c3f2711b59083fff9157c16899da6d4ed76f8eaf57a100fa8'
     ),

    # These are 'speculative', just to cover a few more cases for regressions

    # ssh
    ('c16e1456df150491c50722a9d02fa04c74ef065a94f1936f7db029f71138c239',
     'ssh://jade@jadepin.blockstream.com', 112, 'nist256p1',
     '04a88f160249fd794bdb12fc56896e8dac6bf5e72e33960e2a7d11252f6a93ef28fa183f\
3eca7ac84aa0d2e1488f281dbe4af394fcbeda3ab368e7fe98fc25f16f',
     '00d0472ffa6a6b0075b71a60c7abd3faf9f6d49b7bb86bace344e23c68b888ebc273d48b\
62b4af70f2ad1ca213f6886e26d74d31cfbbd7f4ac917af4d243939813',
     '04ae7218d72039060c69cf50a17698cfe157905e859d7570663c57099e6cf2946be4f6a3\
11f4c3f349b70edea7a8e18b2c2d354811bc5836c713784f72d4d4c201'
     ),
    ('ff732d6499071333f13170d2184054b6dffc1296ca43cb1599a68cea65071e6f',
     'ssh://someuser@github.com', 3754, 'nist256p1',
     '0434e451e9bc1bdba24654822277f5960f42cf6d0375629813d41476c499d62f7d971174\
0406834034958b7782ef743b295530e580bd68a1a1ad3de8b6a141c4c0',
     '00ce030c73249ac7b53184c7987917f00c290ad3b5617c1c0f0465ff150035a46b288766\
c8594e7f574778402c4df5085bfc0642240200ddbe01c0ec9cd2b46a55',
     '04d0ea80cef5fc83d7ac73ae7f33deff8d3b46641d021145cd0d51acf535daa212541315\
630d9e3f99f3adbb652f2178ed7b8190503a3df57dac03c0f9c0ad1d88'
     ),

    # gpg
    ('bcfc224438bd07742c4a3ad6db530e3f071f93645728e9f69eaee21c2f4ed54a',
     'gpg://GreenAddress <greenaddress@blockstream.io>', 0, 'nist256p1',
     '04741f65f95543b6de0ccfcdc13016e573df52fca14b2b15fd3142930bc4d871cc6375a5\
5e402911d873332b8610f73a4020676462c498268a94434a00bca9691e',
     '00010f560db262ee2d82b0032a858d72bb5d927563743af55b3c8514f4c3e353e233e363\
7c172b60b40a48f0c19117ddbd6fc15dcb936430087a86c4db139caa97',
     '0425d63b5f4c41af1d8bee7f6419c28e3d39ec637aef1d5694b008cbc03509c8349f290b\
5937e53105f1aaf613bcf6c72b486015546ee08e7d83412f51f94a6e2a'
     ),
    ('fa94545d4f18e4cc4655c87869fc8a790a07eb58a3e5b599ab9f7da6d8ab5061',
     'gpg://Jade <jade@blockstream.com>', 0, 'nist256p1',
     '041127ef35e4690ff035e13ebab340ab3fa2327c0409bbed3dbf03b8932777d929bd8ade\
43e3ebceb9fc74c23a32cd0e380d9b529a70ee0e83763e0c7af5f0bb1f',
     '000118565f7363337ad72a1c497a1e1de5d336a99b09af8c49b36518e925a0ca517dafff\
b2e95dc777c4d7df504ced12fd668f81a11d14d30033831df1434b59d7',
     '043ede5aad3f3171b495b68da5c36d35eb724e4cb3beafa08b529830bf7679b955730684\
7b8f392c6288ce45565c3133301811f5dcfa6e216e4ae2397e22603e52'
     )
]


# The tests
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
        assert error['message'] == 'Invalid RPC Request message'
        assert int(error['data']) == len(msgbytes)
        assert 'result' not in reply


def test_very_bad_message(jade):
    empty = cbor.dumps(b"")
    text = cbor.dumps("This is not a good cbor message")
    truncated = cbor.dumps("{'id': '1', method: 'msgwillbecut'}")[1:]
    goodmsg = jade.build_request('ent', 'add_entropy', {'entropy': 'noise'.encode()})

    for badmsg in [empty, text, truncated]:
        # Send the bad message, and after a pause a good message
        jade.write(badmsg)
        time.sleep(3)
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
            assert error['message'] == 'Invalid RPC Request message'
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

    time.sleep(5)
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
        assert error['message'] == 'Invalid RPC Request message'
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
    # Adjust the expected_overflow_len for the cbor overhead
    big_msg = cbor.dumps({'method': 'toobig', 'id': 'tohandle', 'params': cacophony})

    # Send the message up with 4k writes
    # (as if trying to write too much can hit the timeout)
    total_len = len(big_msg)
    expected_overflow_len = total_len - expected_buffer_size
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
    assert error['message'] == 'Invalid RPC Request message'
    assert int(error['data']) == expected_buffer_size

    # After a short pause send a good message
    time.sleep(5)
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
        assert error['message'] == 'Invalid RPC Request message'
        bad_bytes += int(error['data'])

    assert bad_bytes == expected_overflow_len

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
                  ('protocol6', 'get_signature'),
                  ('protocol7', 'get_extended_data')]

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
             '02000000010f757ae0b5714cb36e017dfffafe5f3ba8c89ddb969a0ae60d99ee\
7b5892a2740000000000ffffffff01203f0f00000000001600145f4fcd4a757c2abf6a0691f59d\
ffae18852bbd7300000000')

    MULTI_COSIGNERS = [
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
    # Default test user is cosigners[1]
    bad_multi_cosigners1 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners1[1]['fingerprint'] = h2b("abcdef")
    bad_multi_cosigners2 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners2[1]['fingerprint'] = bad_multi_cosigners2[0]['fingerprint']
    bad_multi_cosigners3 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners3[1]['derivation'] = [1, 2, 3, 4]
    bad_multi_cosigners4 = copy.deepcopy(MULTI_COSIGNERS)
    bad_multi_cosigners4[1]['path'] = [2147483648]

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
                  (('badent4', 'add_entropy', {'entropy': ''}), 'valid entropy bytes'),
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
                      'variant': 'sh(wsh(multi(k)))', 'threshold': 1, 'signers': MULTI_COSIGNERS,
                      'master_blinding_key': 1234}}),
                   'Invalid blinding key'),
                  (('badmulti20', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'wsh(multi(k))', 'threshold': 1, 'signers': MULTI_COSIGNERS,
                      'master_blinding_key': 'abcdef'}}),
                   'Invalid blinding key'),
                  (('badmulti21', 'register_multisig',
                    {'network': 'testnet', 'multisig_name': 'test', 'descriptor': {
                      'variant': 'sh(wsh(multi(k)))', 'threshold': 1, 'signers': MULTI_COSIGNERS,
                      'master_blinding_key': EXPECTED_MASTER_BLINDING_KEY[:-1]}}),
                   'Invalid blinding key'),

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
                  (('baddescr6', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test',
                     'descriptor': "wsh(pk(" + DESCR_SIGNER + "))"}),
                   'Failed to extract valid parameter values'),
                  (('baddescr7', 'register_descriptor',
                    {'network': 'testnet', 'descriptor_name': 'test', 'descriptor': DESCRIPTOR,
                     'datavalues': "Wrong type"}), 'Failed to extract valid parameter values'),
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
                    {'network': 'liquid', 'descriptor_name': 'isgood', 'descriptor': DESCRIPTOR,
                     'datavalues': {'@0': DESCR_SIGNER}}), 'not supported on liquid'),

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
                    {'branch': 0, 'pointer': 1, 'descriptor_name': 'looksvalid',
                     'network': 'liquid'}), 'not supported on liquid'),
                  (('badrecvaddr18', 'get_receive_address',
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
                  (('badbip85ent9', 'get_bip85_bip39_entropy',
                    {'num_words': 24, 'index': 0, 'pubkey': GOOD_ECDH_PUBKEY[:-1]}),
                   'fetch valid pubkey'),

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


def test_bad_params_liquid(jade, has_psram, has_ble):

    GOODTX = h2b(
             '0200000000012413047d152348db4342763a0eece0d99e6e2983b3b46eda07ed\
e58d28f201ad0100000000ffffffff020a2b712848b6f14697590b06622266e8d82cb06030896d\
e79700b15562a20834fb0881e4ace4be80524bcc4f566e46a452ab5f43a49929cbf5743d9e1de8\
79a478a7033fc2cd1c4ce77e4339984f786dba6591bd862cf397e8cb6a99e457e162cad68617a9\
142e0ef2990318d8c9f7cee627650ba2a84fdda449870125b251070e29ca19043cf33ccd7324e2\
ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000f4240000000000000')

    GOOD_COMMITMENT = EXPECTED_LIQ_COMMITMENT_2.copy()
    GOOD_COMMITMENT['blinding_key'] = EXPECTED_BLINDING_KEY
    GOOD_COMMITMENTS = [GOOD_COMMITMENT, {}]  # add a null for the unblind output

    BADVAL32 = EXPECTED_LIQ_COMMITMENT_1['abf']
    BADVAL33 = EXPECTED_LIQ_COMMITMENT_1['value_commitment']

    # Correct lengths, prefixes, etc.
    BAD_ASSET_PROOF = h2b("0100017454d5579ec0def281d4712c832e98af69208af4146ba\
691841d6605088e16c55cb5bffdbad36202475d94dea902fbcfa8c428ab7b3901e92df8b201ac865da3")
    BAD_VALUE_PROOF = h2b("200000000000047f47eb9b2f9267f23f7f64c6f93ab7cb7311b\
305abe97f4ac7877e981ffc7d4f662052de1efc379c28cf17f887e92208e70739e1e7abd095227587a895589e725de8")

    GOOD_ASSET = {
        "asset_id": "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5",
        "contract": {
            "entity": {
                "domain": "liquidtestnet.com"
            },
            "issuer_pubkey": "035d0f7b0207d9cc68870abfef621692bce082084ed3ca0c1ae432dd12d889be01",
            "name": "Testnet Asset",
            "precision": 3,
            "ticker": "TEST",
            "version": 0
        },
        "issuance_prevout": {
            "txid": "0e19e938c74378ae83b549213a12be88ede6e32e1407bfdf50c4ec3f927408ec",
            "vout": 0
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
                  (('badsignliq17', 'sign_liquid_tx',  # Bad change outputs
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': []}), 'Unexpected number of output entries'),
                  (('badsignliq18', 'sign_liquid_tx',  # paths missing
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': [{}, {}]}), 'Failed to extract valid receive path'),
                  (('badsignliq19', 'sign_liquid_tx',  # descriptor wallet
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': [{}, {}],
                     'change': [{'descriptor_name': 'looksvalid', 'is_change': True,
                                 'branch': 1, 'pointer': 13}, {}]}), 'not supported on liquid'),

                  (('badsignliq20', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET1]}), 'Invalid asset info passed'),
                  (('badsignliq21', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET2]}), 'Invalid asset info passed'),
                  (('badsignliq22', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET3]}), 'Invalid asset info passed'),
                  (('badsignliq23', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET4]}), 'Invalid asset info passed'),
                  (('badsignliq24', 'sign_liquid_tx',
                    {'network': 'localtest-liquid', 'txn': GOODTX,
                     'num_inputs': 1, 'trusted_commitments': GOOD_COMMITMENTS,
                     'change': None, 'asset_info': [BAD_ASSET5]}), 'Invalid asset info passed')]

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
                        (_commitsMinus('asset_id'), 'extract trusted commitments'),
                        (_commitsMinus('value'), 'extract trusted commitments'),
                        (_commitsMinus('abf'), 'extract trusted commitments'),
                        (_commitsMinus('vbf'), 'extract trusted commitments'),
                        (_commitsMinus('blinding_key'), 'Missing commitments data'),
                        # Field bad type/length etc.
                        (_commitsUpdate('asset_id', 'notbin'), 'extract trusted commitments'),
                        (_commitsUpdate('asset_id', '123abc'), 'extract trusted commitments'),
                        (_commitsUpdate('value', 'notint'), 'extract trusted commitments'),
                        (_commitsUpdate('abf', 'notbin'), 'extract trusted commitments'),
                        (_commitsUpdate('abf', '123abc'), 'extract trusted commitments'),
                        (_commitsUpdate('vbf', 'notbin'), 'extract trusted commitments'),
                        (_commitsUpdate('vbf', '123abc'), 'extract trusted commitments'),
                        (_commitsUpdate('asset_generator', 'notbin'), 'extract trusted commit'),
                        (_commitsUpdate('asset_generator', '123abc'), 'extract trusted commit'),
                        (_commitsUpdate('value_commitment', 'notbin'), 'extract trusted commit'),
                        (_commitsUpdate('value_commitment', '123abc'), 'extract trusted commit'),
                        (_commitsUpdate('blinding_key', 'notbin'), 'Missing commitments data'),
                        (_commitsUpdate('blinding_key', '123abc'), 'Missing commitments data'),
                        # Field bad value
                        (_commitsUpdate('asset_id', BADVAL32), 'verify blinded asset generator'),
                        (_commitsUpdate('abf', BADVAL32), 'verify blinded asset generator'),
                        (_commitsUpdate('vbf', BADVAL32), 'verify blinded value commitment'),
                        (_commitsUpdate('asset_generator', BADVAL33), 'blinded asset generator'),
                        (_commitsUpdate('value_commitment', BADVAL33), 'blinded value commitment'),
                        # Asset blind proof in place of abf
                        (_commitsAssetBlindProof(''), 'extract trusted commitments'),
                        (_commitsAssetBlindProof('notbin'), 'extract trusted commitments'),
                        (_commitsAssetBlindProof('123abc'), 'extract trusted commitments'),
                        # Value blind proof in place of vbf
                        (_commitsValueBlindProof(''), 'extract trusted commitments'),
                        (_commitsValueBlindProof('notbin'), 'extract trusted commitments'),
                        (_commitsValueBlindProof('123abc'), 'extract trusted commitments')]
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


def _set_wallet(jade, mnemonic=TEST_MNEMONIC, passphrase=None):
    # Set mnemonic
    request = jade.build_request("id_mnem", "debug_set_mnemonic",
                                 {"mnemonic": mnemonic, "passphrase": passphrase})
    reply = jade.make_rpc_call(request)
    assert reply['id'] == request['id']
    assert 'error' not in reply
    assert reply['result'] is True

    # Get and return root xpub
    request = jade.build_request("id_xpub", "get_xpub",
                                 {"network": "mainnet", "path": []})
    reply = jade.make_rpc_call(request)
    assert reply['id'] == request['id']
    assert 'error' not in reply
    assert reply['result'].startswith('xpub')
    return reply['result']


def test_mnemonic_import(jade):

    # Check the mnemonic unique prefixes expands to the same mnemonic/wallet
    # as when giving the full mnemonic words (test for qr-scanning prefixes)
    # as the unambiguous prefixes are expanded to the full words.  orc -> orchard
    # Also check the SeedSigner formats also (SeeqQR and CompactSeedQR)
    xpub_root0 = _set_wallet(jade, mnemonic=TEST_MNEMONIC)
    xpub_root1 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_PREFIXES)
    xpub_root2 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_SEEDSIGNER)
    xpub_root3 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_SEEDSIGNER_COMPACT)
    assert xpub_root1 == xpub_root0
    assert xpub_root2 == xpub_root0
    assert xpub_root3 == xpub_root0

    # Check that mnemonic-prefixes are accepted even if they are prefixes to multiple
    # words, provided one of them is an exact/full match for the entire word.
    # eg. 'pen' is a prefix to 'pen', 'penalty' and 'pencil' - but is accepted as it
    # is an exact full match for 'pen', so no 'expansion' is carried out.  pen -> pen.
    xpub_root2 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_PREFIXES_EXACT_MATCH)
    assert xpub_root2 != xpub_root0

    # Seedsigner's own test vectors
    # See: https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md
    for mnem_string, seeqr_numeric, compact_bin in SEEDSIGNER_MNEMONIC_TEST_VECTORS:
        xpub_root0 = _set_wallet(jade, mnemonic=mnem_string)
        xpub_root1 = _set_wallet(jade, mnemonic=seeqr_numeric)
        xpub_root2 = _set_wallet(jade, mnemonic=compact_bin)
        assert xpub_root1 == xpub_root0
        assert xpub_root2 == xpub_root0

    # bcur's bip39 own test case (12-words)
    xpub_root0 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_BCUR_BIP39_STRING)
    xpub_root1 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_BCUR_BIP39_LOWER)
    xpub_root2 = _set_wallet(jade, mnemonic=TEST_MNEMONIC_BCUR_BIP39_UPPER)
    assert xpub_root1 == xpub_root0
    assert xpub_root2 == xpub_root0


def test_mnemonic_import_bad(jade):
    # Check that mnemonic-prefixes are rejected if the prefixes match multiple words
    # (but none of them exactly/full-match).  ie. prefix is ambiguous.  met -> metal, method
    for i, bad_mnemonic in enumerate([TEST_MNEMONIC_PREFIXES_AMBIGUOUS,
                                      TEST_MNEMONIC_SEEDSIGNER[:-1],  # bad length
                                      TEST_MNEMONIC_SEEDSIGNER + '1234',  # bad length
                                      TEST_MNEMONIC_SEEDSIGNER[:-4] + '2048',  # out of range
                                      TEST_MNEMONIC_SEEDSIGNER[:-4] + '0000',  # invalid mnemonic
                                      TEST_MNEMONIC_SEEDSIGNER_COMPACT[:-1],  # bad length
                                      ]):
        request = jade.build_request("badmnemonic_" + str(i), "debug_set_mnemonic",
                                     {"mnemonic": bad_mnemonic})
        reply = jade.make_rpc_call(request)
        assert reply['id'] == request['id']
        assert 'result' not in reply
        assert reply['error']['code'] == JadeError.BAD_PARAMETERS
        assert reply['error']['message'].startswith('Failed to expand mnemonic prefixes')


def test_passphrase(jade):
    # Set mnemonic with/without a passphrase, and get root xpub
    xpub0 = _set_wallet(jade, passphrase=None)
    xpub1 = _set_wallet(jade, passphrase="Passphrase1")
    xpub2 = _set_wallet(jade, passphrase="Passphrase2")

    # Check root xpubs are not the same
    # ie. that the passphrase leads to a different wallet
    assert xpub0 != xpub1 and xpub1 != xpub2 and xpub2 != xpub0

    # Check that using the same passphrase does get the same wallet
    xpub0_again = _set_wallet(jade, passphrase=None)
    xpub1_again = _set_wallet(jade, passphrase="Passphrase1")
    xpub2_again = _set_wallet(jade, passphrase="Passphrase2")

    assert xpub0_again == xpub0 and xpub1_again == xpub1 and xpub2_again == xpub2


# Test qr scanning - can be slow as image data large (slow to upload) and
# tests involve starting the camera (and associated tasks).
def test_scan_qr(jadeapi):
    for qr_data in _get_test_cases(QR_SCAN_TESTS):
        expected = qr_data['expected_output']
        image_filename = qr_data['input']['image']
        with open('./test_data/' + image_filename, 'rb') as f:
            image_data = f.read()

        rslt = jadeapi.scan_qr(image_data)
        assert rslt

        if expected.get("text") is not None:
            assert rslt.decode() == expected["text"]
        else:
            assert rslt == h2b(expected["hex"])


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
    for field, limit in [('JADE_FREE_HEAP', 1536),
                         ('JADE_FREE_DRAM', 1536),
                         ('JADE_LARGEST_DRAM', 4096 if check_frag else -1),
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
            if commitments \
              and 'asset_generator' in commitments and 'value_commitment' in commitments:
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
            sighash = inputdata.get('sighash', wally.WALLY_SIGHASH_ALL)

            # Get the signature message hash (ie. the hash value that was signed)
            tx_flags = wally.WALLY_TX_FLAG_USE_WITNESS if inputdata['is_witness'] else 0
            if is_liquid:
                msghash = wally.tx_get_elements_signature_hash(
                    txn, i, inputdata['script'], inputdata.get('value_commitment'),
                    sighash, tx_flags)
            else:
                if inputdata.get('input_tx'):
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
                    txn, i, inputdata['script'], satoshi, sighash, tx_flags)

            # Check trailing sighash byte and verify signature!
            assert int.from_bytes(signature[-1:], 'little') == sighash
            rawsig = wally.ec_sig_from_der(signature[:-1])  # truncate sighash byte
            host_entropy = inputdata.get('ae_host_entropy') if use_ae_signatures else None
            _verify_signature(jadeapi, network, msghash, inputdata['path'],
                              host_entropy, signer_commitment, rawsig)


def test_set_pinserver(jadeapi):
    # Update pinserver details - just check the calls do not error
    # See test_handshake() above for more in-depth test of this functionality
    with open(PINSERVER_TEST_PUBKEY_FILE, 'rb') as f:
        pubkey = f.read()
    rslt = jadeapi.set_pinserver('https://192.168.0.123:8080',
                                 'http://somelongstringblahblahblah.onion',
                                 pubkey,
                                 'testcertalsoshouldreallybeprettylong')
    assert rslt
    rslt = jadeapi.reset_pinserver(True, True)
    assert rslt


def test_bip85_bip39_encrypted_entropy(jadeapi):
    # Get the Jade test mnemonic master key locally so we can verify the
    # bip85_bip39 entropy returned from jade with libwally
    seed = wally.bip39_mnemonic_to_seed512(TEST_MNEMONIC, None)
    local_master_key = wally.bip32_key_from_seed(seed, wally.BIP32_VER_MAIN_PRIVATE, 0)
    label = 'bip85_bip39_entropy'.encode()

    for nwords, index, expected_mnemonic in GET_BIP85_BIP39_DATA:
        # get new ephemeral key
        while True:
            try:
                privkey = os.urandom(32)
                wally.ec_private_key_verify(privkey)
                break
            except Exception:
                pass

        pubkey = wally.ec_public_key_from_private_key(privkey)

        # Get encrypted bip85 bip39 data from Jade
        rslt = jadeapi.get_bip85_bip39_entropy(nwords, index, pubkey)
        encrypted = rslt['encrypted'][:-32]
        hmac = rslt['encrypted'][-32:]

        # Calculate the shared secret and the two further derived keys
        shared_secret = wally.ecdh(rslt['pubkey'], privkey)
        key_data = wally.hmac_sha512(shared_secret, label)
        encryption_key = key_data[:32]
        hmac_key = key_data[32:]

        # Verify the hmac is correct
        assert wally.hmac_sha256(hmac_key, encrypted) == hmac

        iv = encrypted[:wally.AES_BLOCK_LEN]
        encrypted_entropy = encrypted[wally.AES_BLOCK_LEN:]
        jade_entropy = wally.aes_cbc(encryption_key, iv, encrypted_entropy, wally.AES_FLAG_DECRYPT)

        # Check against libwally when calculated locally
        expected_entropy = wally.bip85_get_bip39_entropy(local_master_key, None, nwords, index)
        assert jade_entropy == expected_entropy

        # TODO: uncomment when libwally released and python dependency updated
        # Test using 'all-in-one' wally function
        # jade_entropy = wally.aes_cbc_with_ecdh_key(privkey, None, rslt['encrypted'],
        #                                            rslt['pubkey'], label, wally.AES_FLAG_DECRYPT)
        # assert jade_entropy == expected_entropy

        # Check against explicit mnemonic words if passed
        if expected_mnemonic:
            jade_mnemonic = wally.bip39_mnemonic_from_bytes(None, jade_entropy)
            assert jade_mnemonic == expected_mnemonic


def test_get_greenaddress_receive_address(jadeapi):
    for network, subact, branch, ptr, recovxpub, csvblocks, conf, expected in GET_GREENADDRESS_DATA:
        rslt = jadeapi.get_receive_address(network, subact, branch, ptr, recovery_xpub=recovxpub,
                                           csv_blocks=csvblocks, confidential=conf)
        assert rslt == expected


def test_get_singlesig_receive_address(jadeapi):
    for network, variant, conf, path, expected in GET_SINGLE_SIG_ADDR_DATA:
        rslt = jadeapi.get_receive_address(network, path, variant=variant, confidential=conf)
        assert rslt == expected


def test_get_xpubs(jadeapi):
    for path, network, expected in GET_XPUB_DATA:
        rslt = jadeapi.get_xpub(network, path)
        assert rslt == expected


def test_sign_message(jadeapi):
    for msg_data in _get_test_cases(SIGN_MSG_TESTS):
        inputdata = msg_data['input']
        rslt = jadeapi.sign_message(inputdata['path'],
                                    inputdata['message'],
                                    inputdata.get('use_ae_signatures'),
                                    inputdata.get('ae_host_commitment'),
                                    inputdata.get('ae_host_entropy'))

        # Check returned signature
        _check_msg_signature(jadeapi, msg_data, rslt)


def test_sign_message_file(jadeapi):
    for msg_data in _get_test_cases(SIGN_MSG_FILE_TESTS):
        inputdata = msg_data['input']
        expected_output = msg_data.get('expected_output')
        expected_error = msg_data.get('expected_error')
        assert expected_output or expected_error

        try:
            rslt = jadeapi.sign_message_file(inputdata['filedata'])
            assert expected_error is None, 'Expected error: ' + expected_error
            assert rslt == expected_output, 'Expected output: ' + expected_output
        except JadeError as e:
            assert expected_output is None, 'Expected output: ' + expected_output
            assert e.message == expected_error, 'Expected error: ' + expected_error


def test_sign_tx(jadeapi, pattern):
    for txn_data in _get_test_cases(pattern):
        inputdata = txn_data['input']
        rslt = jadeapi.sign_tx(inputdata['network'],
                               inputdata['txn'],
                               inputdata['inputs'],
                               inputdata['change'],
                               inputdata.get('use_ae_signatures'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, txn_data, rslt)


def test_sign_tx_error_cases(jadeapi, pattern):
    # Sign Tx failures
    for txn_data in _get_test_cases(pattern):
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


def test_liquid_blinding_keys(jadeapi):
    # Check Jade's master blinding key is as expected and is consistent with wally
    seed = wally.bip39_mnemonic_to_seed512(TEST_MNEMONIC, None)
    master_blinding_key = wally.asset_blinding_key_from_seed(seed)
    assert EXPECTED_MASTER_BLINDING_KEY == master_blinding_key[32:]  # 2nd half of full 512bits

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


def test_liquid_blinded_commitments(jadeapi):

    # Test Jade's values are as expected and are consistent with wally
    abf = wally.asset_blinding_key_to_abf(EXPECTED_MASTER_BLINDING_KEY, TEST_HASH_PREVOUTS, 3)
    vbf = wally.asset_blinding_key_to_vbf(EXPECTED_MASTER_BLINDING_KEY, TEST_HASH_PREVOUTS, 3)

    # Get Liquid blinding factor
    rslt = jadeapi.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'ASSET')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['abf']
    assert rslt == abf

    rslt = jadeapi.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'VALUE')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['vbf']
    assert rslt == vbf

    rslt = jadeapi.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'ASSET_AND_VALUE')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['abf'] + EXPECTED_LIQ_COMMITMENT_1['vbf']
    assert rslt == abf + vbf

    # Get Liquid commitments without custom VBF
    rslt = jadeapi.get_commitments(TEST_REGTEST_BITCOIN,
                                   9000000,
                                   TEST_HASH_PREVOUTS,
                                   3)
    assert rslt == EXPECTED_LIQ_COMMITMENT_1

    # Get Liquid commitments with custom VBF
    rslt = jadeapi.get_commitments(TEST_REGTEST_BITCOIN,
                                   9000000,
                                   TEST_HASH_PREVOUTS,
                                   0,
                                   EXPECTED_LIQ_COMMITMENT_2['vbf'])
    assert rslt == EXPECTED_LIQ_COMMITMENT_2

    # This checks that we get the same blinders and commitments as we got
    # using a ledger.  See also test_data/txn_liquid_ledger_compare.json,
    # which is the same tx as ledger-signed liquid tx:
    # 4b4a27e482eff9dbaa52e7bada4cd7115c299c8e6ac8ebbd20e8d923ad2dad00
    # - and gets the same blinders and the same final signatures.

    ledger_txs = list(_get_test_cases('liquid_txn_ledger_compare.json'))
    assert len(ledger_txs) == 1
    ledger_commitments = ledger_txs[0]['input']['trusted_commitments']
    assert len(ledger_commitments) == 3
    assert ledger_commitments[2] is None

    # Get the hash-prevout for that transaction
    txn = wally.tx_from_bytes(ledger_txs[0]['input']['txn'], wally.WALLY_TX_FLAG_USE_ELEMENTS)
    hash_prevouts = bytes(wally.tx_get_hash_prevouts(txn, 0, 0xffffffff))

    # Sanity check it, since we know what it should be ...
    assert hash_prevouts == h2b('7e78263a58236ffd160ee5a2c58c18b71637974aa95e1c72070b08208012144f')

    # First output commitments, no custom vbf
    rslt = jadeapi.get_commitments(ledger_commitments[0]['asset_id'],
                                   ledger_commitments[0]['value'],
                                   hash_prevouts,
                                   0)
    del ledger_commitments[0]['blinding_key']
    assert rslt == ledger_commitments[0]

    # Second output commitments, including custom vbf
    rslt = jadeapi.get_commitments(ledger_commitments[1]['asset_id'],
                                   ledger_commitments[1]['value'],
                                   hash_prevouts,
                                   1,
                                   ledger_commitments[1]['vbf'],)
    del ledger_commitments[1]['blinding_key']
    assert rslt == ledger_commitments[1]


def test_sign_liquid_tx(jadeapi, has_psram, has_ble, pattern):
    for txn_data in _get_test_cases(pattern):
        inputdata = txn_data['input']
        if not has_psram:
            # Skip any liquid txns too large for reduced message buffer on no-psram devices
            if len(inputdata['txn']) > (15 * 1024):  # esitimate 1k for rest of message fields
                logger.warning("Skipping test - tx too large for non-psram device")
                continue

            # Skip any explicit proof tests which cannot be handled by no-psram devices
            if any(tcs and ('value_blind_proof' in tcs or 'asset_blind_proof' in tcs)
                    for tcs in inputdata['trusted_commitments']):
                logger.warning("Skipping test - explicit proofs too large for non-psram device")
                continue

        rslt = jadeapi.sign_liquid_tx(inputdata['network'],
                                      inputdata['txn'],
                                      inputdata['inputs'],
                                      inputdata['trusted_commitments'],
                                      inputdata['change'],
                                      inputdata.get('use_ae_signatures'),
                                      inputdata.get('asset_info'),
                                      inputdata.get('additional_info'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, txn_data, rslt)


def test_sign_psbt(jadeapi, cases):
    for txn_data in _get_test_cases(cases):
        rslt = jadeapi.sign_psbt(txn_data['input']['network'], txn_data['input']['psbt'])
        assert rslt == txn_data['expected_output']['psbt'], base64.b64encode(rslt).decode()

        # Optionally test extracted tx
        expected_txn = txn_data['expected_output'].get('txn')
        if expected_txn:
            psbt = wally.psbt_from_bytes(rslt)
            wally.psbt_finalize(psbt)
            assert wally.psbt_is_finalized(psbt)
            txn = wally.psbt_extract(psbt)
            txn = wally.tx_to_bytes(txn, wally.WALLY_TX_FLAG_USE_WITNESS)
            assert txn == expected_txn, wally.hex_from_bytes(txn)


# Helper to check a multisig registration
def _check_multisig_registration(jadeapi, multisig_data):
    # Register the multisig
    inputdata = multisig_data['input']
    descriptor = inputdata['descriptor']
    rslt = jadeapi.register_multisig(inputdata['network'],
                                     inputdata['multisig_name'],
                                     descriptor['variant'],
                                     descriptor['sorted'],
                                     descriptor['threshold'],
                                     descriptor['signers'],
                                     master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt is True

    # Check present and correct in 'get_registered_multisigs'
    registered_multisigs = jadeapi.get_registered_multisigs()
    multisig_desc = registered_multisigs.get(inputdata['multisig_name'])
    assert multisig_desc is not None
    assert multisig_desc['variant'] == descriptor['variant']
    assert multisig_desc['sorted'] == descriptor['sorted']
    assert multisig_desc['threshold'] == descriptor['threshold']
    assert multisig_desc['num_signers'] == len(descriptor['signers'])
    assert multisig_desc['master_blinding_key'] == descriptor.get('master_blinding_key', b'')

    # This includes 'get receive address' tests ...
    for addr_test in multisig_data['address_tests']:
        rslt = jadeapi.get_receive_address(inputdata['network'],
                                           addr_test['paths'],
                                           multisig_name=inputdata['multisig_name'])
        assert rslt == addr_test['expected_address']

    # ... and maybe blinding key tests ...
    for blinding_test in multisig_data.get('blinding_key_tests', []):
        rslt = jadeapi.get_blinding_key(blinding_test['script'],
                                        multisig_name=inputdata['multisig_name'])
        assert rslt == blinding_test['expected_blinding_key']

        rslt = jadeapi.get_shared_nonce(blinding_test['script'],
                                        blinding_test['their_pubkey'],
                                        multisig_name=inputdata['multisig_name'])
        assert rslt == blinding_test['expected_shared_nonce']

        rslt = jadeapi.get_shared_nonce(blinding_test['script'],
                                        blinding_test['their_pubkey'],
                                        include_pubkey=True,
                                        multisig_name=inputdata['multisig_name'])
        assert rslt['blinding_key'] == blinding_test['expected_blinding_key']
        assert rslt['shared_nonce'] == blinding_test['expected_shared_nonce']

    # ... and blinding/commitments tests!
    for blinding_test in multisig_data.get('commitments_tests', []):
        for bf_type, rslt_key in [('ASSET', 'abf'), ('VALUE', 'vbf')]:
            rslt = jadeapi.get_blinding_factor(blinding_test['hash_prevouts'],
                                               blinding_test['output_index'],
                                               bf_type,
                                               multisig_name=inputdata['multisig_name'])
            assert rslt == blinding_test[rslt_key]

        rslt = jadeapi.get_commitments(blinding_test['asset_id'],
                                       blinding_test['value'],
                                       blinding_test['hash_prevouts'],
                                       blinding_test['output_index'],
                                       multisig_name=inputdata['multisig_name'])
        assert rslt['abf'] == blinding_test['abf']
        assert rslt['vbf'] == blinding_test['vbf']
        assert rslt['asset_generator'] == blinding_test['asset_generator']
        assert rslt['value_commitment'] == blinding_test['value_commitment']


def test_generic_multisig_registration(jadeapi):
    # Generic multisig - check register multisig wallets and get receive addresses
    for multisig_data in _get_test_cases(MULTI_REG_TESTS):
        _check_multisig_registration(jadeapi, multisig_data)

    # Ensure the 1of1 is registered at the end - same name will be used to overwrite
    # any large test cases (eg. nof15) that otherwise consume all the storage space.
    for multisig_data in _get_test_cases('test_data/multisig_reg_1of1.json'):
        inputdata = multisig_data['input']
        descriptor = inputdata['descriptor']
        rslt = jadeapi.register_multisig(inputdata['network'],
                                         inputdata['multisig_name'],
                                         descriptor['variant'],
                                         descriptor['sorted'],
                                         descriptor['threshold'],
                                         descriptor['signers'],
                                         master_blinding_key=descriptor.get('master_blinding_key'))
        assert rslt


def test_generic_multisig_files(jadeapi):
    # Check these multisig files load ok
    for multisig_file_test in _get_test_cases(MULTI_REG_FILE_TESTS):
        expected_result = multisig_file_test['expected_result']
        multisig_filename = multisig_file_test['input']['multisig_file']
        with open('./test_data/' + multisig_filename, 'r') as f:
            multisig_file = f.read()

        rslt = jadeapi.register_multisig_file(multisig_file)
        assert rslt

        # Check registered as expected
        registered_multisigs = jadeapi.get_registered_multisigs()
        multisig_desc = registered_multisigs.get(expected_result['multisig_name'])
        assert multisig_desc is not None
        assert multisig_desc['sorted'] == expected_result['sorted']
        assert multisig_desc['variant'] == expected_result['variant']
        assert multisig_desc['threshold'] == expected_result['threshold']
        assert multisig_desc['num_signers'] == expected_result['num_signers']
        assert multisig_desc['master_blinding_key'] == \
            expected_result.get('master_blinding_key', b'')

    # Check these multisig files *do not* load
    for multisig_file_test in _get_test_cases(MULTI_REG_BAD_FILE_TESTS):
        expected_error = multisig_file_test['expected_error']
        multisig_filename = multisig_file_test['input']['multisig_file']
        with open('./test_data/' + multisig_filename, 'r') as f:
            multisig_file = f.read()

        try:
            jadeapi.register_multisig_file(multisig_file)
            assert False, 'Expected error: ' + expected_error
        except JadeError as e:
            assert e.message == expected_error, "Expected: " + expected_error


def test_generic_multisig_matches_ga_addresses(jadeapi):
    # This test checks that the generic multisig wallets 'matches_ga', do...
    # ie. if I use the standard ga receive-address, I get the same result as
    # that using 'generic multisig' (as the co-signers are set-up to match green)
    matching_ga_msigs = _get_test_cases('multisig_reg_*matches_ga_*.json')
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
            assert all(p == [ptr] for p in addr_test['paths'])
            rslt = jadeapi.get_receive_address(inputdata['network'], subaccount, branch, ptr,
                                               recovery_xpub=recovery_xpub)
            assert rslt == addr_test['expected_address']

    # ... and maybe blinding key tests ...
    for blinding_test in ga_msig.get('blinding_key_tests', []):
        rslt = jadeapi.get_blinding_key(blinding_test['script'])
        assert rslt == blinding_test['expected_blinding_key']

        rslt = jadeapi.get_shared_nonce(blinding_test['script'],
                                        blinding_test['their_pubkey'])
        assert rslt == blinding_test['expected_shared_nonce']

        rslt = jadeapi.get_shared_nonce(blinding_test['script'],
                                        blinding_test['their_pubkey'],
                                        include_pubkey=True)
        assert rslt['blinding_key'] == blinding_test['expected_blinding_key']
        assert rslt['shared_nonce'] == blinding_test['expected_shared_nonce']

    # ... and blinding/commitments tests!
    for blinding_test in ga_msig.get('commitments_tests', []):
        for bf_type, rslt_key in [('ASSET', 'abf'), ('VALUE', 'vbf')]:
            rslt = jadeapi.get_blinding_factor(blinding_test['hash_prevouts'],
                                               blinding_test['output_index'],
                                               bf_type)
            assert rslt == blinding_test[rslt_key]

        rslt = jadeapi.get_commitments(blinding_test['asset_id'],
                                       blinding_test['value'],
                                       blinding_test['hash_prevouts'],
                                       blinding_test['output_index'],
                                       multisig_name=inputdata['multisig_name'])
        assert rslt['abf'] == blinding_test['abf']
        assert rslt['vbf'] == blinding_test['vbf']
        assert rslt['asset_generator'] == blinding_test['asset_generator']
        assert rslt['value_commitment'] == blinding_test['value_commitment']


def test_generic_multisig_matches_ga_signatures(jadeapi):
    # Sign txns using generic multisig registration - should get same sigs as ga
    ga_2of2_multisig_data = list(_get_test_cases('multisig_reg_matches_ga_2of2.json'))
    assert len(ga_2of2_multisig_data) == 1
    inputdata = ga_2of2_multisig_data[0]['input']
    descriptor = inputdata['descriptor']
    rslt = jadeapi.register_multisig(inputdata['network'],
                                     inputdata['multisig_name'],
                                     descriptor['variant'],
                                     descriptor['sorted'],
                                     descriptor['threshold'],
                                     descriptor['signers'],
                                     master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt

    ga_2of2_multisig_name = inputdata['multisig_name']
    MULTISIG_SIGN_TXS = ['txn_2of2_change.json', 'txn_segwit_multi_input.json']
    ga_2of2_multisig_txns = (list(_get_test_cases(testcase))[0] for testcase in MULTISIG_SIGN_TXS)
    for ga_msig in ga_2of2_multisig_txns:
        inputdata = ga_msig['input']

        # Doctor the change paths to include the registered multisig name, but not
        # the multisig xpub root (ie. to only contain the final 'ptr' part)
        # (as the subact/branch is part of the multisig registration)
        for change in inputdata['change'] or []:
            if change is not None:
                path = change.pop('path')
                change['paths'] = [path[-1:]] * 2
                change['multisig_name'] = ga_2of2_multisig_name

        rslt = jadeapi.sign_tx(inputdata['network'],
                               inputdata['txn'],
                               inputdata.get('inputs'),
                               inputdata['change'],
                               inputdata.get('use_ae_signatures'),
                               )

        # Check returned signatures
        _check_tx_signatures(jadeapi, ga_msig, rslt)


def test_generic_multisig_matches_ga_signatures_liquid(jadeapi):
    # Sign liquid txns using generic multisig registration - should get same sigs as ga
    ga_2of2_multisig_data = list(_get_test_cases('multisig_reg_liquid_matches_ga_2of2.json'))
    assert len(ga_2of2_multisig_data) == 1
    inputdata = ga_2of2_multisig_data[0]['input']
    descriptor = inputdata['descriptor']
    rslt = jadeapi.register_multisig(inputdata['network'],
                                     inputdata['multisig_name'],
                                     descriptor['variant'],
                                     descriptor['sorted'],
                                     descriptor['threshold'],
                                     descriptor['signers'],
                                     master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt

    ga_2of2_multisig_name = inputdata['multisig_name']
    MULTISIG_SIGN_TXS = ['liquid_txn_lowr_nochange.json', 'liquid_txn_noncsv.json']
    ga_2of2_multisig_txns = (list(_get_test_cases(testcase))[0] for testcase in MULTISIG_SIGN_TXS)
    for ga_msig in ga_2of2_multisig_txns:
        inputdata = ga_msig['input']

        # Doctor the change paths to include the registered multisig name, but not
        # the multisig xpub root (ie. to only contain the final 'ptr' part)
        # (as the subact/branch is part of the multisig registration)
        for change in inputdata['change'] or []:
            if change is not None:
                path = change.pop('path')
                change['paths'] = [path[-1:]] * 2
                change['multisig_name'] = ga_2of2_multisig_name

        rslt = jadeapi.sign_liquid_tx(inputdata['network'],
                                      inputdata['txn'],
                                      inputdata.get('inputs'),
                                      inputdata['trusted_commitments'],
                                      inputdata['change'],
                                      inputdata.get('use_ae_signatures'),
                                      inputdata.get('asset_info'),
                                      inputdata.get('additional_info'))

        # Check returned signatures
        _check_tx_signatures(jadeapi, ga_msig, rslt)


def test_generic_multisig_ss_signer(jadeapi):
    # Register multisig wallets again - this checks that a second user from the multisig
    # gets the same receive-address.  ie. in the tests 'multisig_reg_ss' the 'single sig'
    # signer is also in the multisig, so we can check it from this signer also.
    for multisig_data in _get_test_cases(MULTI_REG_SS_TESTS):
        # Test trying to access the multisig description registered under the
        # main test mnemonic fails (as must be registered by accessing wallet)
        inputdata = multisig_data['input']
        descriptor = inputdata['descriptor']
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
        _check_multisig_registration(jadeapi, multisig_data)


def test_miniscript_descriptor_registration(jadeapi):
    for descriptor_data in _get_test_cases(DESCRIPTOR_REG_SS_TESTS):
        # Register the descriptor
        inputdata = descriptor_data['input']
        rslt = jadeapi.register_descriptor(inputdata['network'],
                                           inputdata['descriptor_name'],
                                           inputdata['descriptor'],
                                           inputdata.get('datavalues'))
        assert rslt is True

        # Check present and correct in 'get_registered_descriptors'
        # registered_descriptors = jadeapi.get_registered_descriptors()
        # descriptor_desc = registered_descriptors.get(inputdata['descriptor_name'])
        # assert descriptor_desc is not None
        # assert descriptor_desc['descriptor'] == inputdata['descriptor']
        # assert descriptor_desc['datavalues'] == descriptor['datavalues']

        # This includes 'get receive address' tests ...
        for addr_test in descriptor_data['address_tests']:
            rslt = jadeapi.get_receive_address(inputdata['network'],
                                               addr_test['branch'],
                                               addr_test['pointer'],
                                               descriptor_name=inputdata['descriptor_name'])
            assert rslt == addr_test['expected_address']

        # Check multisig equivalent if provided
        if 'multisig_equivalent' in inputdata:
            # Register the multisig equivalent
            descriptor = inputdata['multisig_equivalent']['descriptor']
            rslt = jadeapi.register_multisig(inputdata['network'],
                                             inputdata['descriptor_name'],
                                             descriptor['variant'],
                                             descriptor['sorted'],
                                             descriptor['threshold'],
                                             descriptor['signers'],
                                             None)  # blinding key
            assert rslt is True

            # Check the receive addresses are the same
            for addr_test in descriptor_data['address_tests']:
                paths = [[addr_test['branch'], addr_test['pointer']]] * len(descriptor['signers'])
                rslt = jadeapi.get_receive_address(inputdata['network'],
                                                   paths,
                                                   multisig_name=inputdata['descriptor_name'])
                assert rslt == addr_test['expected_address']


def test_miniscript_descriptor_registration_ss_signer(jadeapi):
    test_miniscript_descriptor_registration(jadeapi)  # for now ...


def test_12word_mnemonic(jadeapi):
    # Short sanity-test of 12-word mnemonic
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC_12)
    assert rslt is True
    rslt = jadeapi.get_xpub('mainnet', [1, 12])
    assert rslt == 'xpub6BETMaQnyXi1gqFdL5FX8A3YEtRCEvBPijmr7EL42rGeEc6pvjYv25\
ZoxpDgc3UZwmpCgfdCkNmcSQa2tjnZLPohvRFECZP9P1boFKdJ5Sx'
    rslt = jadeapi.get_receive_address('mainnet', 1, 1, 231)
    assert rslt == '38SBTKLCNKVvQh1jPpbkAbXa3gtRJEh9Ud'


def test_sign_identity(jadeapi):
    ecdh_nist_cpty = list(_get_test_cases('identity_ssh_nist_matches_trezor.json'))[0]
    for identity_data in _get_test_cases(SIGN_IDENTITY_TESTS):
        inputdata = identity_data['input']
        expected = identity_data['expected_output']

        # Check get-pubkey call for slip-0013 and slip-0017
        for pubkey_type in ['slip-0013', 'slip-0017']:
            rslt = jadeapi.get_identity_pubkey(inputdata['identity'],
                                               inputdata['curve'],
                                               pubkey_type,
                                               inputdata['index'])
            assert rslt == expected[pubkey_type]

        # Sign for an identity using a given curve (slip-0013)
        rslt = jadeapi.sign_identity(inputdata['identity'],
                                     inputdata['curve'],
                                     inputdata['challenge'],
                                     inputdata['index'])
        assert rslt['pubkey'] == expected['slip-0013']
        assert rslt['signature'] == expected['signature']

        # Symmetry test for ecdh 'shared key'
        # Note the 3rd param is the 'other party public key' (slip-0017)
        assert ecdh_nist_cpty['input']['curve'] == inputdata['curve']
        ecdhA = jadeapi.get_identity_shared_key(inputdata['identity'],
                                                inputdata['curve'],
                                                ecdh_nist_cpty['expected_output']['slip-0017'],
                                                index=inputdata['index'])
        ecdhB = jadeapi.get_identity_shared_key(ecdh_nist_cpty['input']['identity'],
                                                ecdh_nist_cpty['input']['curve'],
                                                expected['slip-0017'],
                                                index=ecdh_nist_cpty['input']['index'])
        # Assert symmetry
        assert ecdhA == expected['ecdh_with_trezor']
        assert ecdhA == ecdhB


# Test according to otp spec (rfc6238)
def test_hotp(jadeapi):
    hotp_name = 'test_hotp'
    hotp_uri = 'otpauth://hotp/ACME%20Co:john.doe@email.com\
?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&counter={}'

    # Register HOTP record
    rslt = jadeapi.register_otp(hotp_name, hotp_uri.format(0))
    assert rslt

    expected_results = ['755224', '287082', '359152', '969429', '338314',
                        '254676', '287922', '162583', '399871', '520489']

    # Fetch repeated codes 'naturally'
    for expected in expected_results:
        rslt = jadeapi.get_otp_code(hotp_name)
        assert rslt == expected

    # Fetch repeated codes explicitly passing the counter
    for i, expected in enumerate(expected_results):
        rslt = jadeapi.get_otp_code(hotp_name, value_override=i)
        assert rslt == expected

    # Check can register with an 'initial counter' - eg. starting from 5
    startfrom = 5
    rslt = jadeapi.register_otp(hotp_name, hotp_uri.format(startfrom))
    assert rslt

    # Fetch repeated codes 'naturally' from the explicit start point
    for expected in expected_results[startfrom:]:
        rslt = jadeapi.get_otp_code(hotp_name)
        assert rslt == expected


# Test according to otp spec (rfc6238)
def test_totp(jadeapi):
    totp_name = 'test_totp'
    totp_uri = 'otpauth://totp/ACME%20Co:john.doe@email.com\
?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&digits=8&algorithm={}'

    timestamps = [59, 1111111109, 1111111111,
                  1234567890, 2000000000, 20000000000]

    expected_results = [
      ('SHA1',
       ('94287082', '07081804', '14050471',
        '89005924', '69279037', '65353130')),
      ('SHA256',
       ('46119246', '68084774', '67062674',
        '91819424', '90698825', '77737706')),
      ('SHA512',
       ('90693936', '25091201', '99943326',
        '93441116', '38618901', '47863826'))
    ]

    for algo, expected in expected_results:
        rslt = jadeapi.register_otp(totp_name, totp_uri.format(algo))
        assert rslt

        # Fetch code 'naturally' - can't verify result but just see that it works
        rslt = jadeapi.get_otp_code(totp_name)
        assert len(rslt) == 8

        # Fetch repeated codes explicitly passing the timestamp
        for i, timestamp in enumerate(timestamps):
            rslt = jadeapi.get_otp_code(totp_name, value_override=timestamp)
            assert rslt == expected[i]


# NOTE:
# There is some uncertainty around secrets padding when shorter than the hash size.
# rfc6238 test vectors appear to suggest the secrets should be lengthened by repetition to the
# length of the hash, although gauth-like implementations do not appear to do this - rather
# they just use the short secret as is.
# To maintain maximum compatibility we do not lengthen the secret for SHA1 *only*, and we do
# lengthen short secrets for other hash digest algorithms.
# This provides compatability with gauth-like services, and should also remain compatible with
# HOTP/SHA1 which does not extend the secrets.
def test_totp_ex(jadeapi):
    # Short secret - not padded/lengthened for SHA1 for maximum gauth compatibility
    totp_name = 'test_totp_ex'
    totp_uri = 'otpauth://totp/ACM?secret=VMR466AB62ZBOKHE&digits=6&algorithm=SHA1'
    rslt = jadeapi.register_otp(totp_name, totp_uri)
    assert rslt

    # Fetch repeated codes explicitly passing the timestamp
    ts_rslt = [(0, '538532'), (1426847216, '543160')]
    for timestamp, expected in ts_rslt:
        rslt = jadeapi.get_otp_code(totp_name, value_override=timestamp)
        assert rslt == expected

    # Short secret - not padded for gauth/SHA1
    totp_name = 'test_totp_ex'
    totp_uri = 'otpauth://totp/Foo?secret=VM'
    rslt = jadeapi.register_otp(totp_name, totp_uri)
    assert rslt

    # Fetch repeated codes explicitly passing the timestamp
    ts_rslt = [(1659641526, '468828'), (1659641674, '550073'), (1659641710, '222948')]
    for timestamp, expected in ts_rslt:
        rslt = jadeapi.get_otp_code(totp_name, value_override=timestamp)
        assert rslt == expected

    # Long secret for SHA512 - padded if required
    totp_name = 'test_totp_ex'
    totp_uri = 'otpauth://totp/Foo\
?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDG\
NBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&digits=8&algorithm=SHA512'
    rslt = jadeapi.register_otp(totp_name, totp_uri)
    assert rslt

    # Fetch repeated codes explicitly passing the timestamp
    ts_rslt = [(59, '90693936'),
               (1111111109, '25091201'),
               (1111111111, '99943326'),
               (1234567890, '93441116'),
               (2000000000, '38618901'),
               (20000000000, '47863826')]
    for timestamp, expected in ts_rslt:
        rslt = jadeapi.get_otp_code(totp_name, value_override=timestamp)
        assert rslt == expected


def test_ping_protocol(jade):
    # Random ae data as irrelevant, so long as same in both cases
    signmsg = jade.build_request('signABC', 'sign_message',
                                 {'path': [0, 16],
                                  'message': 'TestABC',
                                  'ae_host_commitment': os.urandom(32)})
    getsig = jade.build_request('getsigABC', 'get_signature',
                                {'ae_host_entropy': os.urandom(32)})

    # Uninterrupted flow
    commitABC1 = jade.make_rpc_call(signmsg)['result']
    sigABC1 = jade.make_rpc_call(getsig)['result']

    # Same messages but with a 'ping' packet between protocol messages
    commitABC2 = jade.make_rpc_call(signmsg)['result']
    assert commitABC2 == commitABC1

    jade_is_busy = jade.make_rpc_call(jade.build_request('pingNOW', 'ping'))['result']
    assert jade_is_busy == 1  # handling a message (the sign-msg sent above)

    verinfo = jade.make_rpc_call(jade.build_request('verInfoNOW', 'get_version_info',
                                                    {'nonblocking': True}))['result']
    assert len(verinfo) == NUM_VALUES_VERINFO

    sigABC2 = jade.make_rpc_call(getsig)['result']
    assert sigABC2 == sigABC1

    jade_is_busy = jade.make_rpc_call(jade.build_request('pingAGAIN', 'ping'))['result']
    assert jade_is_busy == 0  # idle


def run_api_tests(jadeapi, isble, qemu, authuser=False):

    rslt = jadeapi.clean_reset()
    assert rslt is True

    rslt = jadeapi.ping()
    assert rslt == 0  # idle

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

    rslt = jadeapi.ping()
    assert rslt == 0  # idle

    startinfo = jadeapi.get_version_info()
    assert len(startinfo) == NUM_VALUES_VERINFO
    has_psram = startinfo['JADE_FREE_SPIRAM'] > 0
    has_ble = startinfo['JADE_CONFIG'] == 'BLE'

    # Test logout
    assert startinfo['JADE_STATE'] == 'READY'
    jadeapi.logout()
    assert jadeapi.get_version_info()['JADE_STATE'] in ['LOCKED', 'UNINIT']
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert jadeapi.get_version_info()['JADE_STATE'] == "READY"

    # Test update pinserver details
    test_set_pinserver(jadeapi)

    # Test BIP85 entropy
    test_bip85_bip39_encrypted_entropy(jadeapi)

    # Test generic multisig
    test_generic_multisig_registration(jadeapi)
    test_generic_multisig_matches_ga_addresses(jadeapi)
    test_generic_multisig_matches_ga_signatures(jadeapi)
    test_generic_multisig_matches_ga_signatures_liquid(jadeapi)
    test_generic_multisig_files(jadeapi)

    # Test descriptor wallets
    test_miniscript_descriptor_registration(jadeapi)

    # Get (receive) green-addresses, get-xpub, and sign-message
    test_get_greenaddress_receive_address(jadeapi)
    test_get_xpubs(jadeapi)
    test_sign_message(jadeapi)
    test_sign_message_file(jadeapi)

    # Sign Tx - includes some failure cases
    test_sign_tx(jadeapi, SIGN_TXN_TESTS)
    test_sign_tx_error_cases(jadeapi, SIGN_TXN_FAIL_CASES)

    # Test liuid blinding keys/nonce, blinded commitments and sign-tx
    test_liquid_blinding_keys(jadeapi)
    test_liquid_blinded_commitments(jadeapi)
    test_sign_liquid_tx(jadeapi, has_psram, has_ble, SIGN_LIQUID_TXN_TESTS)

    # Test sign psbts (app-generated cases)
    test_sign_psbt(jadeapi, SIGN_PSBT_TESTS)

    # Short sanity-test of 12-word mnemonic
    test_12word_mnemonic(jadeapi)

    # Sign single sig
    # Single sig requires a different seed for the tests
    rslt = jadeapi.set_seed(bytes.fromhex(TEST_SEED_SINGLE_SIG))
    assert rslt is True

    # Test the generic multisigs again, using a second signer
    # NOTE: some of these tests assume 'test_generic_multisig_registration()' test
    # has already been run, to register the multisigs for the test mnemonic signer
    test_generic_multisig_ss_signer(jadeapi)

    # Test the descriptor wallets again, using a second signer
    # NOTE: some of these tests assume 'test_miniscript_descriptor_registration()' test
    # has already been run, to register the descriptors for the test mnemonic signer
    test_miniscript_descriptor_registration_ss_signer(jadeapi)

    test_get_singlesig_receive_address(jadeapi)
    test_sign_tx(jadeapi, SIGN_TXN_SINGLE_SIG_TESTS)
    test_sign_liquid_tx(jadeapi, has_psram, has_ble, SIGN_LIQUID_TXN_SINGLE_SIG_TESTS)

    # Test sign psbts (HWI-generated cases)
    test_sign_psbt(jadeapi, SIGN_PSBT_SS_TESTS)

    # Sign identity (ssh & gpg) tests require a specific mnemonic
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC_12_IDENTITY)
    assert rslt is True

    test_sign_identity(jadeapi)

    # Test OTP (hotp and totp)
    # (These don't depend on the wallet/mnemonic, just that the hw is unlocked)
    test_hotp(jadeapi)
    test_totp(jadeapi)
    test_totp_ex(jadeapi)

    # restore the mnemonic
    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    time.sleep(5)  # Lets idle tasks clean up
    endinfo = jadeapi.get_version_info()

    # NOTE: skip the fragmentation check when we have BLE enabled
    # as there is too much memory allocation outside of our control.
    # Also skip for no-psram (qemu) devices.
    check_frag = has_psram and not has_ble
    check_mem_stats(startinfo, endinfo, check_frag=check_frag)


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

    rslt = jadeapi.ping()
    assert rslt == 0  # idle

    rslt = jadeapi.set_mnemonic(TEST_MNEMONIC)
    assert rslt is True

    rslt = jadeapi.ping()
    assert rslt == 0  # idle

    startinfo = jadeapi.get_version_info()
    assert len(startinfo) == NUM_VALUES_VERINFO
    has_psram = startinfo['JADE_FREE_SPIRAM'] > 0
    has_ble = startinfo['JADE_CONFIG'] == 'BLE'

    rslt = jadeapi.get_version_info(nonblocking=True)
    assert len(rslt) == NUM_VALUES_VERINFO
    assert rslt['EFUSEMAC'] == startinfo['EFUSEMAC']
    assert rslt['JADE_CONFIG'] == startinfo['JADE_CONFIG']
    assert rslt['JADE_VERSION'] == startinfo['JADE_VERSION']
    assert rslt['JADE_STATE'] == startinfo['JADE_STATE']

    # Smoke tests
    if smoke:
        logger.info("Smoke tests")

        # Sanity check selfcheck time on Jade hw (skip for qemu)
        # May need updating if more tests added to selfcheck.c
        time_ms = jadeapi.run_remote_selfcheck()
        logger.info('selfcheck time: ' + str(time_ms) + 'ms')
        assert qemu or time_ms < 82500

        # Test good pinserver handshake, and also 'bad sig' pinserver
        test_handshake(jadeapi.jade)
        test_handshake_bad_sig(jadeapi.jade)

        # Test importing mnemonic words eg. from qr scan
        test_mnemonic_import(jadeapi.jade)
        test_mnemonic_import_bad(jadeapi.jade)

        # Test mnemonic-with-passphrase
        test_passphrase(jadeapi.jade)

        # Test ping doesn't break signing protocol
        test_ping_protocol(jadeapi.jade)

        # Only run QR scan/camera tests a) over serial, and b) on proper Jade hw
        if not qemu and not isble and startinfo['BOARD_TYPE'] in ['JADE', 'JADE_V1.1']:
            test_scan_qr(jadeapi)

    # Too much input test - sends a lot of data so only run
    # if not running over BLE (as would take a long time)
    if not isble:
        logger.info("Buffer overflow test - PSRAM: {}".format(has_psram))
        test_too_much_input(jadeapi.jade, has_psram)

    # Negative tests
    if negative:
        logger.info("Negative tests")
        test_random_bytes(jadeapi.jade)
        test_very_bad_message(jadeapi.jade)
        test_bad_message(jadeapi.jade)
        test_split_message(jadeapi.jade)
        test_concatenated_messages(jadeapi.jade)
        test_unknown_method(jadeapi.jade)
        test_unexpected_method(jadeapi.jade)
        test_bad_params(jadeapi.jade)
        test_bad_params_liquid(jadeapi.jade, has_psram, has_ble)

    time.sleep(5)  # Lets idle tasks clean up
    endinfo = jadeapi.get_version_info()

    # NOTE: skip the fragmentation check when we have BLE enabled
    # as there is too much memory allocation outside of our control.
    # Also skip for no-psram (qemu) devices.
    check_frag = has_psram and not has_ble
    check_mem_stats(startinfo, endinfo, check_frag=check_frag)


# Run all selected tests over a passed JadeAPI instance.
def run_jade_tests(jadeapi, args, isble):
    logger.info(f"Running selected Jade tests over passed connection, is_ble={isble}")

    # Low-level JadeInterface tests
    if not args.skiplow:
        run_interface_tests(jadeapi, isble, args.qemu, authuser=args.authuser)

    # High-level JadeAPI tests
    if not args.skiphigh:
        run_api_tests(jadeapi, isble, args.qemu, authuser=args.authuser)


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
        assert False, "Expected exception from mixed sources test"
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
                                   timeout=args.serialtimeout) as jade:
            run_jade_tests(jade, args, isble=False)

    # 2. Test over BLE connection
    if not args.skipble:
        if info['JADE_CONFIG'] == 'BLE':
            bleid = info['EFUSEMAC'][6:]
            logger.info("Testing BLE ({})".format(bleid))
            with JadeAPI.create_ble(serial_number=bleid) as jade:
                run_jade_tests(jade, args, isble=True)

                # 3. If also testing over serial, run the 'mixed sources' tests
                if not args.skipserial:
                    logger.info("Running 'mixed sources' Tests")
                    with JadeAPI.create_serial(args.serialport,
                                               timeout=args.serialtimeout) as jadeserial:
                        mixed_sources_test(jadeserial, jade)
        else:
            msg = "Skipping BLE tests - not enabled on the hardware"
            logger.warning(msg)


# Connect to Jade by serial or BLE and get the info block
def get_jade_info(args):
    if not args.skipserial:
        logger.info("Getting info via Serial ({})".format(args.serialport))
        with JadeAPI.create_serial(device=args.serialport,
                                   timeout=args.serialtimeout) as jade:
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
    timeout = 45  # minutes
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
                        default=None)

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

    skpgrp = parser.add_mutually_exclusive_group()
    skpgrp.add_argument("--skiplow",
                        action="store_true",
                        dest="skiplow",
                        help="Skip low-level JadeInterface (negative) tests",
                        default=False)
    skpgrp.add_argument("--skiphigh",
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

    parser.add_argument("--serialtimeout",
                        action="store",
                        dest="serialtimeout",
                        type=int,
                        help="Serial port timeout",
                        default=DEFAULT_SERIAL_TIMEOUT)
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
        logger.error("Can only skip one of Serial or BLE tests, not both!")
        os.exit(1)

    if args.bleid and not args.skipserial:
        logger.error("Can only supply ble-id when skipping serial tests")
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
            #    logger.info("Testing BLE fails with incorrect passkey")
            #    btgent = start_agent(BLE_TEST_BADKEYFILE)
            #    test_ble_connection_fails(info, args)
        else:
            assert False, "Can't connect to Jade over serial or BLE"
    finally:
        if btagent:
            kill_agent(btagent)
