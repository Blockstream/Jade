from . import *
from .test_multisig import TEST_SEED_SINGLE_SIG

LIQUID_DESCRIPTORS = True
# The master blinding key resulting from default mnemonic
DEFAULT_MNEMONIC_MASTER_BLINDING_KEY = \
    'afacc503637e85da661ca1706c4ea147f1407868c48d8f92dd339ac272293cdc'


def test_descriptor_slip77_network_rules(jade):
    descriptor_no_slip77 = 'wsh(pkh(@0/<0;1>/*))'
    descriptor_with_slip77 = 'ct(slip77(@B),wpkh(@0/<0;1>/*))'
    signer = "[e3ebcc79/48'/1'/0'/2']tpubDDvj9CrVJ9kWXSL2kjtA8v53rZvTmL3HmWPvgD3hiTnD5KZuMkxSUsgGra\
Z9vavB5JSA3F9s5E4cXuCte5rvBs5N4DjfxYssQk1L82Bq4FE"
    blinding_key = DEFAULT_MNEMONIC_MASTER_BLINDING_KEY

    if LIQUID_DESCRIPTORS:
        # Liquid descriptor with SLIP-77 should pass
        assert jade.register_descriptor(
            'localtest-liquid', 'liqs77ok', descriptor_with_slip77,
            {'@B': blinding_key, '@0': signer}) is True

        # Liquid descriptor without SLIP-77 should fail.
        check_bad_params(
            jade.jade,
            ('liq_s77_miss', 'register_descriptor',
             {'network': 'localtest-liquid', 'descriptor_name': 'liqnos77',
              'descriptor': descriptor_no_slip77, 'datavalues': {'@0': signer}}),
            'must use slip77 blinding for liquid network')
    else:
        # Liquid descriptors disabled: reject liquid descriptors up-front
        check_bad_params(
            jade.jade,
            ('liq_s77_off', 'register_descriptor',
             {'network': 'localtest-liquid', 'descriptor_name': 'liqoff77',
              'descriptor': descriptor_with_slip77,
              'datavalues': {'@B': blinding_key, '@0': signer}}),
            'not supported on liquid')

    # Non-liquid descriptor with SLIP-77 should fail
    check_bad_params(
        jade.jade,
        ('btc_s77_bad', 'register_descriptor',
         {'network': 'testnet', 'descriptor_name': 'btcs77bad',
          'descriptor': descriptor_with_slip77,
          'datavalues': {'@B': blinding_key, '@0': signer}}),
        'Descriptor must not be confidential for bitcoin network')

    # Non-liquid descriptor without SLIP-77 should pass.
    assert jade.register_descriptor(
      'testnet', 'btcnos77', descriptor_no_slip77, {'@0': signer}) is True


@with_test_cases('tests/rpc/data/descriptor/descriptor_*.json')
def test_miniscript_descriptor_registration(jade, test_case):
    """Test descriptor wallets"""
    _test_miniscript_descriptor_registration(jade, test_case)


@pytest.mark.mnemonic(mnemonics.invalidatecache)
@pytest.mark.seed(seeds.singlesig)
@with_test_cases('tests/rpc/data/descriptor/descriptor_ss_*.json')
def test_miniscript_descriptor_registration_ss(jade, test_case):
    """Test the descriptor wallets again, using a second signer"""
    _test_miniscript_descriptor_registration(jade, test_case)


def _test_miniscript_descriptor_registration(jade, test_case):
    # Register the descriptor
    inputdata = test_case['input']

    rslt = jade.register_descriptor(inputdata['network'],
                                    inputdata['descriptor_name'],
                                    inputdata['descriptor'],
                                    inputdata.get('datavalues'))
    assert rslt is True

    # Pull the data back, then reload (roundtrip) - should be a no-op
    roundtrip = jade.get_registered_descriptor(inputdata['descriptor_name'])
    assert roundtrip is not None
    assert roundtrip['descriptor'] == inputdata['descriptor']
    assert roundtrip.get('datavalues') == inputdata.get('datavalues')

    roundtrip['network'] = inputdata['network']  # the only item not roundtripped
    rslt = jade._jadeRpc('register_descriptor', roundtrip)  # push result structure back
    assert rslt

    # Check present and correct in 'get_registered_multisigs' also
    registered_descriptors = jade.get_registered_descriptors()
    descriptor_desc = registered_descriptors.get(inputdata['descriptor_name'])
    assert descriptor_desc is not None
    assert descriptor_desc['descriptor_len'] == len(inputdata['descriptor'])
    assert descriptor_desc['num_datavalues'] == len(inputdata.get('datavalues', []))

    # This includes 'get receive address' tests ...
    for addr_test in test_case['address_tests']:
        rslt = jade.get_receive_address(inputdata['network'],
                                        addr_test['branch'],
                                        addr_test['pointer'],
                                        descriptor_name=inputdata['descriptor_name'])
        assert rslt == addr_test['expected_address']

    # Check multisig equivalent if provided
    if 'multisig_equivalent' in inputdata:
        # Register the multisig equivalent
        descriptor = inputdata['multisig_equivalent']['descriptor']
        rslt = jade.register_multisig(inputdata['network'],
                                      inputdata['descriptor_name'],
                                      descriptor['variant'],
                                      descriptor['sorted'],
                                      descriptor['threshold'],
                                      descriptor['signers'],
                                      None)  # blinding key
        assert rslt is True

        # Check the receive addresses are the same
        for addr_test in test_case['address_tests']:
            paths = [[addr_test['branch'], addr_test['pointer']]] * len(descriptor['signers'])
            rslt = jade.get_receive_address(inputdata['network'],
                                            paths,
                                            multisig_name=inputdata['descriptor_name'])
            assert rslt == addr_test['expected_address']
