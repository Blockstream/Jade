from . import *
from .test_multisig import TEST_SEED_SINGLE_SIG


@with_test_cases('tests/rpc/data/address/greenaddress.json')
def test_get_greenaddress_receive_address(jade, test_case):
    for network, subact, branch, ptr, recovxpub, csvblocks, conf, expected in test_case:
        rslt = jade.get_receive_address(network, subact, branch, ptr, recovery_xpub=recovxpub,
                                        csv_blocks=csvblocks, confidential=conf)
        assert rslt == expected


@pytest.mark.mnemonic(mnemonics.invalidatecache)
@pytest.mark.seed(seeds.singlesig)
@with_test_cases('tests/rpc/data/address/single_sig_addr.json')
def test_get_singlesig_receive_address(jade, mnemonic, test_case):
    # Testcased were generated on core
    for network, variant, conf, path, expected in test_case:
        rslt = jade.get_receive_address(network, path, variant=variant, confidential=conf)
        assert rslt == expected


@with_test_cases('tests/rpc/data/address/xpub.json')
def test_get_xpubs(jade, test_case):
    # NOTE: for get-xpub the root (empty path array) can be accessed (to allow
    # external creation of watch-only public key tree)
    # NOTE: networks 'liquid' and 'mainnet' result in 'xpub' prefix, else 'tpub'
    for path, network, expected in test_case:
        rslt = jade.get_xpub(network, path)
        assert rslt == expected
