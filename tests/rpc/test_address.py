from . import *
from .test_multisig import TEST_SEED_SINGLE_SIG


@with_test_cases('tests/rpc/data/address/greenaddress.json')
def test_get_greenaddress_receive_address(jade, test_case):
    for network, subact, branch, ptr, recovxpub, csvblocks, conf, expected in test_case:
        rslt = jade.get_receive_address(network, subact, branch, ptr, recovery_xpub=recovxpub,
                                        csv_blocks=csvblocks, confidential=conf)
        assert rslt == expected


@pytest.mark.mnemonic(mnemonics.singlesig_seed)
@with_test_cases('tests/rpc/data/address/single_sig_addr.json')
def test_get_singlesig_receive_address(jade, mnemonic, test_case):
    for network, variant, conf, path, expected in test_case:
        rslt = jade.get_receive_address(network, path, variant=variant, confidential=conf)
        assert rslt == expected


def test_get_p2pkh_descriptor_receive_address(jade):
    # p2pkh (testnet) xpub for the default mnemonic
    p2pkh = "[e3ebcc79/44'/1'/0']" + \
            "tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZz" + \
            "TcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk"
    assert jade.register_descriptor('testnet', 'testp2pkh', 'pkh(@0/<0;1>/*)',
                                    {'@0': p2pkh}) is True

    def get_addr(branch, pointer):
        return jade.get_receive_address('testnet', branch, pointer,
                                        descriptor_name='testp2pkh')

    cases = [
        (0, 1,          'mxZ9D9v3PZMxGwQXTiD4GZcNeDHVspFkPC'),
        (1, 0,          'mxmsGjuPdMS1i2aJWVCQbrCZfMW8zAbakv'),
        (2, 0,          None),  # Invalid multi-index
        (0, 0x80000000, None),  # Hardened child
    ]

    for branch, pointer, expected in cases:
        if expected:
            assert get_addr(branch, pointer) == expected
        else:
            with pytest.raises(JadeError):
                get_addr(branch, pointer)


@with_test_cases('tests/rpc/data/address/xpub.json')
def test_get_xpubs(jade, test_case):
    # NOTE: for get-xpub the root (empty path array) can be accessed (to allow
    # external creation of watch-only public key tree)
    # NOTE: networks 'liquid' and 'mainnet' result in 'xpub' prefix, else 'tpub'
    for path, network, expected in test_case:
        rslt = jade.get_xpub(network, path)
        assert rslt == expected
