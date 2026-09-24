# FIXME: Add tests for:
# - Mixed wallet and non-wallet inputs
# - Unusual input and change paths
# - Negative test cases (invalid PSBTs)
from . import *


def _test_sign_psbt(jade, test_case):
    psbt_bin = test_case['input']['psbt']

    expect_pset_failure = False
    if not get_jade_config().has_psram:
        # Max message size from main/process.h
        # 69 bytes of overhead for a sign_psbt request
        MAX_INPUT_MSG_SIZE = 1024 * 17 + 69
        if len(psbt_bin) + 69 > MAX_INPUT_MSG_SIZE:
            pytest.skip(f'Skipping {test_case["filename"]} large PSBT (no-psram)')
        if psbt_bin[2] == ord('e'):
            # Expect PSET test cases to fail for non-PSRAM devices
            expect_pset_failure = True
            return  # Silently skip

    try:
        network = test_case['input']['network']
        additional_info = test_case['input'].get('additional_info')
        rslt = jade.sign_psbt(network, psbt_bin, additional_info)
    except JadeError as err:
        if expect_pset_failure:
            return  # Trying to parse a PSET on an unsupported device
        assert 'expected_output' not in test_case, f'FAILED: {err.message}: {test_case}'
        # Check expected error
        assert err.message == test_case['expected_error'], err.message
        return

    # Otherwise, should have worked, check expected output
    assert 'expected_error' not in test_case
    assert rslt == test_case['expected_output']['psbt'], base64.b64encode(rslt).decode()

    # Optionally test extracted tx
    expected_tx = test_case['expected_output'].get('txn')
    if expected_tx:
        psbt = wally.psbt_from_bytes(rslt, 0)
        wally.psbt_finalize(psbt, 0)
        # Extract finalized inputs where possible (e.g. multisigs may
        # not be fully signed and thus aren't finalizable)
        tx = wally.psbt_extract(psbt, wally.WALLY_PSBT_EXTRACT_OPT_FINAL)
        tx = wally.tx_to_bytes(tx, wally.WALLY_TX_FLAG_USE_WITNESS)
        assert tx == expected_tx, tx.hex()


@with_test_cases('tests/rpc/data/sign_psbt/psbt_tm_*.json')
def test_sign_psbt(jade, test_case):
    _test_sign_psbt(jade, test_case)


@with_test_cases('tests/rpc/data/sign_psbt/pset_tm_*.json')
def test_sign_pset(jade, mnemonic, test_case):
    _test_sign_psbt(jade, test_case)


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/psbt_ss_*.json')
def test_sign_ss_psbt(jade, mnemonic, test_case):
    _test_sign_psbt(jade, test_case)


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/pset_ss_*.json')
def test_sign_ss_pset(jade, mnemonic, test_case):
    _test_sign_psbt(jade, test_case)


def _psbt_with_padding(psbt_bin, padding_len):
    '''Add a proprietary input field (key 0xfc, id "jade", subtype 0)
       to pad the psbt size without side effects'''
    psbt = wally.psbt_from_bytes(psbt_bin, 0)
    assert wally.psbt_get_input_unknowns_size(psbt, 0) == 0
    unknowns = wally.map_init(1, None)
    wally.map_add(unknowns, b'\xfc\x04jade\x00', bytes(padding_len))
    wally.psbt_set_input_unknowns(psbt, 0, unknowns)
    return wally.psbt_to_bytes(psbt, 0)


@pytest.mark.skipif(transport_is_not('libjade'), reason='libjade only')
@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/psbt_ss_p2tr_default_all.json')
def test_sign_psbt_chunk_boundaries(jade, mnemonic, test_case):
    # PSBT_OUT_CHUNK_SIZE is 3072 - 64 = 3008 in standard builds, including
    # libjade. Test +/-1 of one and two chunks plus exact multiples.
    for output_size in [3007, 3008, 3009, 6015, 6016, 6017]:
        signed_psbt = test_case['expected_output']['psbt']
        padding_len = output_size - len(signed_psbt)
        # Account for the unknown key and CompactSize-encoded key/value lengths.
        padding_len -= len(_psbt_with_padding(signed_psbt, padding_len)) - output_size
        expected_psbt = _psbt_with_padding(signed_psbt, padding_len)
        assert len(expected_psbt) == output_size

        padded_test_case = {
            **test_case,
            'input': {
                **test_case['input'],
                'psbt': _psbt_with_padding(test_case['input']['psbt'], padding_len),
            },
            'expected_output': {**test_case['expected_output'], 'psbt': expected_psbt},
        }
        _test_sign_psbt(jade, padded_test_case)
