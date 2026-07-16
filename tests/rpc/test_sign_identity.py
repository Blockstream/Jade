from . import *
from .. import _get_test_cases


@pytest.mark.mnemonic(mnemonics.identity)
@with_test_cases('tests/rpc/data/sign_identity/identity_*.json')
def test_sign_identity(jade, mnemonic, test_case):
    """Sign identity (ssh & gpg) tests (require a specific mnemonic)"""
    ecdh_nist_cptys = list(
        _get_test_cases('tests/rpc/data/sign_identity/identity_ssh_nist_matches_trezor.json')
    )
    assert len(ecdh_nist_cptys) == 1
    ecdh_nist_cpty = ecdh_nist_cptys[0][0] if ecdh_nist_cptys else None

    inputdata = test_case['input']
    expected = test_case['expected_output']

    # Check get-pubkey call for slip-0013 and slip-0017
    for pubkey_type in ['slip-0013', 'slip-0017']:
        rslt = jade.get_identity_pubkey(inputdata['identity'],
                                        inputdata['curve'],
                                        pubkey_type,
                                        inputdata['index'])
        assert rslt == expected[pubkey_type]

    # Sign for an identity using a given curve (slip-0013)
    rslt = jade.sign_identity(inputdata['identity'],
                              inputdata['curve'],
                              inputdata['challenge'],
                              inputdata['index'])
    assert rslt['pubkey'] == expected['slip-0013']
    assert rslt['signature'] == expected['signature']

    # Symmetry test for ecdh 'shared key'
    # Note the 3rd param is the 'other party public key' (slip-0017)
    if not ecdh_nist_cpty:
        return

    assert ecdh_nist_cpty['input']['curve'] == inputdata['curve']
    ecdhA = jade.get_identity_shared_key(inputdata['identity'],
                                         inputdata['curve'],
                                         ecdh_nist_cpty['expected_output']['slip-0017'],
                                         index=inputdata['index'])
    ecdhB = jade.get_identity_shared_key(ecdh_nist_cpty['input']['identity'],
                                         ecdh_nist_cpty['input']['curve'],
                                         expected['slip-0017'],
                                         index=ecdh_nist_cpty['input']['index'])
    # Assert symmetry
    assert ecdhA == expected['ecdh_with_trezor']
    assert ecdhA == ecdhB
