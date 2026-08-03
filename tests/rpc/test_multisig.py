from . import *
from .. import _get_test_cases
from .test_sign_tx import _check_tx_signatures


TEST_SEED_SINGLE_SIG = 'b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c'


def _check_multisig_registration(jade, multisig_data):
    """Helper to check a multisig registration"""
    # Register the multisig
    inputdata = multisig_data['input']
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'],
                                  master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt is True

    # Pull the data back, then reload (roundtrip) - should be a no-op
    roundtrip = jade.get_registered_multisig(inputdata['multisig_name'])
    fetched = roundtrip['descriptor']
    assert fetched['variant'] == descriptor['variant']
    assert fetched['sorted'] == descriptor['sorted']
    assert fetched['threshold'] == descriptor['threshold']
    assert fetched['master_blinding_key'] == descriptor.get('master_blinding_key', b'')
    assert fetched['signers'] == descriptor['signers']

    roundtrip['network'] = inputdata['network']  # the only item not roundtripped
    if not fetched['master_blinding_key']:
        del fetched['master_blinding_key']  # don't send null/empty blinding key

    rslt = jade._jadeRpc('register_multisig', roundtrip)  # push result structure back
    assert rslt

    # Check present and correct in 'get_registered_multisigs' also
    registered_multisigs = jade.get_registered_multisigs()
    multisig_desc = registered_multisigs.get(inputdata['multisig_name'])
    assert multisig_desc is not None
    assert multisig_desc['variant'] == descriptor['variant']
    assert multisig_desc['sorted'] == descriptor['sorted']
    assert multisig_desc['threshold'] == descriptor['threshold']
    assert multisig_desc['num_signers'] == len(descriptor['signers'])
    assert multisig_desc['master_blinding_key'] == descriptor.get('master_blinding_key', b'')

    # This includes 'get receive address' tests ...
    for addr_test in multisig_data['address_tests']:
        rslt = jade.get_receive_address(inputdata['network'],
                                        addr_test['paths'],
                                        multisig_name=inputdata['multisig_name'])
        assert rslt == addr_test['expected_address']

    # ... and maybe blinding key tests ...
    for blinding_test in multisig_data.get('blinding_key_tests', []):
        rslt = jade.get_blinding_key(blinding_test['script'],
                                     multisig_name=inputdata['multisig_name'])
        assert rslt == blinding_test['expected_blinding_key']

        rslt = jade.get_shared_nonce(blinding_test['script'],
                                     blinding_test['their_pubkey'],
                                     multisig_name=inputdata['multisig_name'])
        assert rslt == blinding_test['expected_shared_nonce']

        rslt = jade.get_shared_nonce(blinding_test['script'],
                                     blinding_test['their_pubkey'],
                                     include_pubkey=True,
                                     multisig_name=inputdata['multisig_name'])
        assert rslt['blinding_key'] == blinding_test['expected_blinding_key']
        assert rslt['shared_nonce'] == blinding_test['expected_shared_nonce']

    # ... and blinding/commitments tests!
    for blinding_test in multisig_data.get('commitments_tests', []):
        for bf_type, rslt_key in [('ASSET', 'abf'), ('VALUE', 'vbf')]:
            rslt = jade.get_blinding_factor(blinding_test['hash_prevouts'],
                                            blinding_test['output_index'],
                                            bf_type,
                                            multisig_name=inputdata['multisig_name'])
            assert rslt == blinding_test[rslt_key]

        rslt = jade.get_commitments(blinding_test['asset_id'],
                                    blinding_test['value'],
                                    blinding_test['hash_prevouts'],
                                    blinding_test['output_index'],
                                    multisig_name=inputdata['multisig_name'])
        assert rslt['abf'] == blinding_test['abf']
        assert rslt['vbf'] == blinding_test['vbf']
        assert rslt['asset_generator'] == blinding_test['asset_generator']
        assert rslt['value_commitment'] == blinding_test['value_commitment']


@with_test_cases('tests/rpc/data/multisig/multisig_reg_*.json')
def test_generic_multisig_registration(jade, test_case):
    """Generic multisig - check register multisig wallets and get receive addresses"""
    # Run all of these tests since later test cases rely on them :(
    _check_multisig_registration(jade, test_case)

    # Ensure the 1of1 is registered at the end - same name will be used to overwrite
    # any large test cases (eg. nof15) that otherwise consume all the storage space.
    for multisig_data, _ in _get_test_cases('tests/rpc/data/multisig/multisig_reg_1of1.json'):
        inputdata = multisig_data['input']
        descriptor = inputdata['descriptor']
        rslt = jade.register_multisig(inputdata['network'],
                                      inputdata['multisig_name'],
                                      descriptor['variant'],
                                      descriptor['sorted'],
                                      descriptor['threshold'],
                                      descriptor['signers'],
                                      master_blinding_key=descriptor.get('master_blinding_key'))
        assert rslt


@with_test_cases('tests/rpc/data/multisig/multisig_file_*.json')
def test_generic_multisig_files(jade, test_case):
    """Check these multisig files load ok"""
    expected_result = test_case['expected_result']
    multisig_filename = test_case['input']['multisig_file']
    with open('tests/rpc/data/multisig/' + multisig_filename, 'r') as f:
        multisig_file = f.read()

    rslt = jade.register_multisig_file(multisig_file)
    assert rslt

    # Pull the data back, then reload (roundtrip) - should be a no-op
    roundtrip = jade.get_registered_multisig(expected_result['multisig_name'], as_file=True)
    rslt = jade.register_multisig_file(roundtrip['multisig_file'])
    assert rslt

    # Check registered as expected
    fetched = jade.get_registered_multisig(expected_result['multisig_name'])
    fetched = fetched['descriptor']
    assert fetched['variant'] == expected_result['variant']
    assert fetched['sorted'] == expected_result['sorted']
    assert fetched['threshold'] == expected_result['threshold']
    assert fetched['master_blinding_key'] == expected_result.get('master_blinding_key', b'')
    assert len(fetched['signers']) == expected_result['num_signers']

    registered_multisigs = jade.get_registered_multisigs()
    multisig_desc = registered_multisigs.get(expected_result['multisig_name'])
    assert multisig_desc is not None
    assert multisig_desc['sorted'] == expected_result['sorted']
    assert multisig_desc['variant'] == expected_result['variant']
    assert multisig_desc['threshold'] == expected_result['threshold']
    assert multisig_desc['num_signers'] == expected_result['num_signers']
    assert multisig_desc['master_blinding_key'] == \
        expected_result.get('master_blinding_key', b'')


@with_test_cases('tests/rpc/data/multisig/multisig_bad_file_*.json')
def test_generic_multisig_bad_files(jade, test_case):
    """Check these multisig files *do not* load"""
    expected_error = test_case['expected_error']
    multisig_filename = test_case['input']['multisig_file']
    with open('tests/rpc/data/multisig/' + multisig_filename, 'r') as f:
        multisig_file = f.read()

    try:
        jade.register_multisig_file(multisig_file)
        assert False, 'Expected error: ' + expected_error
    except JadeError as e:
        assert e.message == expected_error, 'Expected: ' + expected_error


@with_test_cases('tests/rpc/data/multisig/multisig_reg_*matches_ga_*.json')
def test_generic_multisig_matches_ga_addresses(jade, test_case):
    """
    This test checks that the generic multisig wallets 'matches_ga', do...
    ie. if I use the standard ga receive-address, I get the same result as
    that using 'generic multisig' (as the co-signers are set-up to match green)
    """
    inputdata = test_case['input']
    signers = inputdata['descriptor']['signers']

    # Register multisig wallet
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'],
                                  master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt is True

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
        assert False, 'Unexpected derivation for ga-multisig wallet'

    user_xpub = jade.get_xpub(inputdata['network'], user_signer['derivation'])
    assert user_xpub == user_signer['xpub']   # checks our xpub entry
    recovery_xpub = signers[2]['xpub'] if len(signers) == 3 else None

    # Check receive addresses fetched using normal green call matches the
    # expected results (which are tested as a generic multisig address above)
    for addr_test in test_case['address_tests']:
        ptr = addr_test['paths'][0][0]
        # check all signers have same single-entry path (ie. 'ptr')
        assert all(p == [ptr] for p in addr_test['paths'])
        rslt = jade.get_receive_address(inputdata['network'], subaccount, branch, ptr,
                                        recovery_xpub=recovery_xpub)
        assert rslt == addr_test['expected_address']

    # ... and maybe blinding key tests ...
    for blinding_test in test_case.get('blinding_key_tests', []):
        rslt = jade.get_blinding_key(blinding_test['script'])
        assert rslt == blinding_test['expected_blinding_key']

        rslt = jade.get_shared_nonce(blinding_test['script'],
                                     blinding_test['their_pubkey'])
        assert rslt == blinding_test['expected_shared_nonce']

        rslt = jade.get_shared_nonce(blinding_test['script'],
                                     blinding_test['their_pubkey'],
                                     include_pubkey=True)
        assert rslt['blinding_key'] == blinding_test['expected_blinding_key']
        assert rslt['shared_nonce'] == blinding_test['expected_shared_nonce']

    # ... and blinding/commitments tests!
    for blinding_test in test_case.get('commitments_tests', []):
        for bf_type, rslt_key in [('ASSET', 'abf'), ('VALUE', 'vbf')]:
            rslt = jade.get_blinding_factor(blinding_test['hash_prevouts'],
                                            blinding_test['output_index'],
                                            bf_type)
            assert rslt == blinding_test[rslt_key]

        rslt = jade.get_commitments(blinding_test['asset_id'],
                                    blinding_test['value'],
                                    blinding_test['hash_prevouts'],
                                    blinding_test['output_index'],
                                    multisig_name=inputdata['multisig_name'])
        assert rslt['abf'] == blinding_test['abf']
        assert rslt['vbf'] == blinding_test['vbf']
        assert rslt['asset_generator'] == blinding_test['asset_generator']
        assert rslt['value_commitment'] == blinding_test['value_commitment']


@with_test_cases('tests/rpc/data/multisig/multisig_reg_matches_ga_2of2.json')
def test_generic_multisig_matches_ga_signatures(jade, test_case):
    """Sign txns using generic multisig registration - should get same sigs as ga"""
    inputdata = test_case['input']
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'],
                                  master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt

    ga_2of2_multisig_name = inputdata['multisig_name']
    MULTISIG_SIGN_TXS = [
        'tests/rpc/data/multisig/txn_2of2_change.json',
        'tests/rpc/data/multisig/txn_segwit_multi_input.json']
    ga_2of2_multisig_txns = (list(_get_test_cases(testcase))[0][0]
                             for testcase in MULTISIG_SIGN_TXS)
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

        use_ae_signatures = inputdata.get('use_ae_signatures')
        use_legacy_flow = not use_ae_signatures and not get_jade_config().no_legacy_flow
        rslt = jade.sign_tx(inputdata['network'],
                            inputdata['txn'],
                            inputdata.get('inputs'),
                            inputdata['change'],
                            use_ae_signatures,
                            use_legacy_flow)

        # Check returned signatures
        _check_tx_signatures(jade, ga_msig, rslt)


@with_test_cases('tests/rpc/data/multisig/multisig_reg_liquid_matches_ga_2of2.json')
def test_generic_multisig_matches_ga_signatures_liquid(jade, test_case):
    """Sign liquid txns using generic multisig registration - should get same sigs as ga"""
    inputdata = test_case['input']
    descriptor = inputdata['descriptor']
    rslt = jade.register_multisig(inputdata['network'],
                                  inputdata['multisig_name'],
                                  descriptor['variant'],
                                  descriptor['sorted'],
                                  descriptor['threshold'],
                                  descriptor['signers'],
                                  master_blinding_key=descriptor.get('master_blinding_key'))
    assert rslt

    ga_2of2_multisig_name = inputdata['multisig_name']
    MULTISIG_SIGN_TXS = [
                         'tests/rpc/data/multisig/liquid_txn_lowr_nochange.json',
                         'tests/rpc/data/multisig/liquid_txn_noncsv.json'
    ]
    ga_2of2_multisig_txns = (list(_get_test_cases(testcase))[0][0]
                             for testcase in MULTISIG_SIGN_TXS)
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

        rslt = jade.sign_liquid_tx(inputdata['network'],
                                   inputdata['txn'],
                                   inputdata.get('inputs'),
                                   inputdata['trusted_commitments'],
                                   inputdata['change'],
                                   inputdata.get('use_ae_signatures'),
                                   inputdata.get('asset_info'),
                                   inputdata.get('additional_info'))

        # Check returned signatures
        _check_tx_signatures(jade, ga_msig, rslt)


@pytest.mark.mnemonic(mnemonics.invalidatecache)
@pytest.mark.seed(seeds.singlesig)
@with_test_cases('tests/rpc/data/multisig/multisig_reg_ss_*.json')
def test_generic_multisig_ss_signer(jade, mnemonic, test_case):
    """
    Register multisig wallets again - this checks that a second user from the multisig
    gets the same receive-address.  ie. in the tests 'multisig_reg_ss' the 'single sig'
    signer is also in the multisig, so we can check it from this signer also.
    """
    # set_seed() starts with clean_reset(), which removes all registrations.
    # Recreate this wallet under the main signer, then switch to the singlesig
    # signer without resetting so that we can exercise cross-wallet access.
    assert jade.set_mnemonic(mnemonics.default)
    _check_multisig_registration(jade, test_case)
    assert jade.set_seed(bytes.fromhex(TEST_SEED_SINGLE_SIG))

    # Test trying to access the multisig description registered under the
    # main test mnemonic fails (as must be registered by accessing wallet)
    inputdata = test_case['input']
    descriptor = inputdata['descriptor']
    try:
        for addr_test in test_case['address_tests']:
            rslt = jade.get_receive_address(inputdata['network'],
                                            addr_test['paths'],
                                            multisig_name=inputdata['multisig_name'])
            assert False, 'Accessing other wallet multisig should fail'
    except JadeError as e:
        assert e.code == JadeError.BAD_PARAMETERS
        assert e.message == 'Cannot de-serialise multisig wallet data', e.message

    # If we register the same multisig description to this wallet, it should produce
    # the same addresses as it did previously (for the other signatory)
    _check_multisig_registration(jade, test_case)
    pass
