from . import *
from .. import _get_test_cases


EXPECTED_MASTER_BLINDING_KEY = bytes.fromhex('afacc503637e85da661ca1706c4ea147f1407868c4\
8d8f92dd339ac272293cdc')

EXPECTED_BLINDING_KEY = bytes.fromhex('023454c233497be73ed98c07d5e9069e21519e94d0663375c\
a57c982037546e352')

TEST_SCRIPT = bytes.fromhex('76a9145f4fcd4a757c2abf6a0691f59dffae18852bbd7388ac')

TEST_THEIR_PK = bytes.fromhex('03e7cd9230b30bf53753a43add0e88931bac3be21baa4c6465d9f8da9\
251f2904c')

EXPECTED_SHARED_SECRET = bytes.fromhex('35801ebd1e62e8698490440861cff2e5bd10cf4aec19b51f\
8ccc7dc910a7e488')

EXPECTED_MASTER_BLINDING_KEY = bytes.fromhex('afacc503637e85da661ca1706c4ea147f1407868c4\
8d8f92dd339ac272293cdc')

TEST_HASH_PREVOUTS_HEX = '95f17695f6329dbcce2aa0b7f1eaff823b19d64d8737d642d6e6\
147f5ec88342'

TEST_HASH_PREVOUTS = bytes.fromhex(TEST_HASH_PREVOUTS_HEX)

EXPECTED_LIQ_COMMITMENT_1 = {'abf': bytes.fromhex('42bc9c7025f3df490a208cb362ff220547910\
da1d3e81c63a6e7c28c3a33a993'),
                             'vbf': bytes.fromhex('7a6693fde7b88efb8375db618670fb5ccb9b2\
f7e8743b7d772924f0426c5efe6'),
                             'asset_generator': bytes.fromhex('0a5cf0a43ad404163946c28b8\
a36d0e5cb4895b0ee386da4cd1008ffc8cb464501'),
                             'value_commitment': bytes.fromhex('082d8de9b7f66994abf789b2\
591738331f88a7ddbef4e553bbf123e47677d60099'),
                             'asset_id': bytes.fromhex('5ac9f65c0efcc4775e0baec4ec03abdd\
e22473cd3cf33c0419ca290e0751b225'),
                             'value': 9000000}

EXPECTED_LIQ_COMMITMENT_2 = {'abf': bytes.fromhex('a3510210bbab6ed67429af9beaf42f09382e1\
2146a3db466971b58a45516bba0'),
                             'vbf': bytes.fromhex('6ec064a68075a278bfca4a10f777c730116e9\
ba02fbb343a237c847e4d2fbf53'),
                             'asset_generator': bytes.fromhex('0abd23178d9ff73cf848d8d88\
a7c7e269a464f53017cab0f9f53ed9d64b2849713'),
                             'value_commitment': bytes.fromhex('094d9a00f1661a2a805a8afe\
c9c188310d4c43353cc319886ee4d9f439389d8f43'),
                             'asset_id': bytes.fromhex('5ac9f65c0efcc4775e0baec4ec03abdd\
e22473cd3cf33c0419ca290e0751b225'),
                             'value': 9000000}

TEST_REGTEST_BITCOIN = bytes.fromhex('5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419\
ca290e0751b225')


def test_liquid_blinding_keys(jade):
    # Check Jade's master blinding key is as expected and is consistent with wally
    seed = wally.bip39_mnemonic_to_seed512(mnemonics.default, None)
    master_blinding_key = wally.asset_blinding_key_from_seed(seed)
    assert EXPECTED_MASTER_BLINDING_KEY == master_blinding_key[32:]  # 2nd half of full 512bits

    # Get Liquid master blinding key - errors if we pass the 'onlyIfSilent'
    # flag, as would normally block while asking user.
    try:
        rslt = jade.get_master_blinding_key(True)
        assert False, 'Expecting "user declined" error'
    except JadeError as e:
        assert e.code == JadeError.USER_CANCELLED

    # These ask the user to confirm which is fine
    rslt = jade.get_master_blinding_key(False)
    assert rslt == EXPECTED_MASTER_BLINDING_KEY
    rslt = jade.get_master_blinding_key()
    assert rslt == EXPECTED_MASTER_BLINDING_KEY

    # Get Liquid script blinding key
    rslt = jade.get_blinding_key(TEST_SCRIPT)
    assert rslt == EXPECTED_BLINDING_KEY

    # Get Liquid shared nonce
    rslt = jade.get_shared_nonce(TEST_SCRIPT, TEST_THEIR_PK)
    assert rslt == EXPECTED_SHARED_SECRET

    # Get Liquid shared nonce and public blinding key in one call
    rslt = jade.get_shared_nonce(TEST_SCRIPT, TEST_THEIR_PK, include_pubkey=True)
    assert rslt['shared_nonce'] == EXPECTED_SHARED_SECRET
    assert rslt['blinding_key'] == EXPECTED_BLINDING_KEY


def test_liquid_blinded_commitments(jade):
    # Test Jade's values are as expected and are consistent with wally
    abf = wally.asset_blinding_key_to_abf(EXPECTED_MASTER_BLINDING_KEY, TEST_HASH_PREVOUTS, 3)
    vbf = wally.asset_blinding_key_to_vbf(EXPECTED_MASTER_BLINDING_KEY, TEST_HASH_PREVOUTS, 3)

    # Get Liquid blinding factor
    rslt = jade.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'ASSET')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['abf']
    assert rslt == abf

    rslt = jade.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'VALUE')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['vbf']
    assert rslt == vbf

    rslt = jade.get_blinding_factor(TEST_HASH_PREVOUTS, 3, 'ASSET_AND_VALUE')
    assert rslt == EXPECTED_LIQ_COMMITMENT_1['abf'] + EXPECTED_LIQ_COMMITMENT_1['vbf']
    assert rslt == abf + vbf

    # Get Liquid commitments without custom VBF
    rslt = jade.get_commitments(TEST_REGTEST_BITCOIN,
                                9000000,
                                TEST_HASH_PREVOUTS,
                                3)
    assert rslt == EXPECTED_LIQ_COMMITMENT_1

    # Get Liquid commitments with custom VBF
    rslt = jade.get_commitments(TEST_REGTEST_BITCOIN,
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

    ledger_txs = list(_get_test_cases('tests/rpc/data/blindings/liquid_txn_ledger_compare.json'))
    assert len(ledger_txs) == 1
    ledger_commitments = ledger_txs[0][0]['input']['trusted_commitments']
    assert len(ledger_commitments) == 3
    assert ledger_commitments[2] is None

    # Get the hash-prevout for that transaction
    txn = wally.tx_from_bytes(ledger_txs[0][0]['input']['txn'], wally.WALLY_TX_FLAG_USE_ELEMENTS)
    hash_prevouts = bytes(wally.tx_get_hash_prevouts(txn, 0, 0xffffffff))

    # Sanity check it, since we know what it should be ...
    assert hash_prevouts == bytes.fromhex(
        '7e78263a58236ffd160ee5a2c58c18b71637974aa95e1c72070b08208012144f')

    # First output commitments, no custom vbf
    rslt = jade.get_commitments(ledger_commitments[0]['asset_id'],
                                ledger_commitments[0]['value'],
                                hash_prevouts,
                                0)
    del ledger_commitments[0]['blinding_key']
    assert rslt == ledger_commitments[0]

    # Second output commitments, including custom vbf
    rslt = jade.get_commitments(ledger_commitments[1]['asset_id'],
                                ledger_commitments[1]['value'],
                                hash_prevouts,
                                1,
                                ledger_commitments[1]['vbf'],)
    del ledger_commitments[1]['blinding_key']
    assert rslt == ledger_commitments[1]
