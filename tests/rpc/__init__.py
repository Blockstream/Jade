# RPC tests package marker for unittest discovery.
import time

from .. import *


def wait(seconds, force=False):
    """Wait for transport timing-sensitive protocol tests"""
    if force or transport_is_not('libjade'):
        time.sleep(seconds)


def get_genesis_blockhash(network):
    """Returns the genesis blockhash for a given network."""
    if 'liquid' not in network:
        return None
    if 'localtest' in network:
        genesis = '00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21'
    elif 'testnet' in network:
        genesis = 'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1'
    else:
        # Liquid mainnet
        genesis = '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003'
    return bytes.fromhex(genesis)[::-1]


def verify_signature(jade, network, msghash, path,
                     host_entropy, signer_commitment,
                     signature, is_schnorr):
    """
    Helper to verify a signature - handles checking an Anti-Exfil signature
    contains the entropy that was passed in by the host.
    """
    is_liquid = 'liquid' in network
    # entropy/signer_commitment imply anti-exfil signature
    assert (host_entropy is None) == (signer_commitment is None)

    # Need to get the signer's pubkey
    xpub = jade.get_xpub(network, path)
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


def check_bad_params(jade, rpc_args, expected_error):
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
