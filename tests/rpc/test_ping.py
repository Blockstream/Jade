from . import *


NUM_VALUES_VERINFO = 22


def test_ping_protocol(jade):
    """Test ping doesn't break signing protocol"""
    # Random ae data as irrelevant, so long as same in both cases
    signmsg = jade.jade.build_request('signABC', 'sign_message',
                                      {'path': [0, 16],
                                       'message': 'TestABC',
                                       'ae_host_commitment': os.urandom(32)})
    getsig = jade.jade.build_request('getsigABC', 'get_signature',
                                     {'ae_host_entropy': os.urandom(32)})

    # Uninterrupted flow
    commitABC1 = jade.jade.make_rpc_call(signmsg)['result']
    sigABC1 = jade.jade.make_rpc_call(getsig)['result']

    # Same messages but with a 'ping' packet between protocol messages
    commitABC2 = jade.jade.make_rpc_call(signmsg)['result']
    assert commitABC2 == commitABC1

    jade_is_busy = jade.jade.make_rpc_call(jade.jade.build_request('pingNOW', 'ping'))['result']
    assert jade_is_busy == 1  # handling a message (the sign-msg sent above)

    verinfo = jade.jade.make_rpc_call(jade.jade.build_request('verInfoNOW', 'get_version_info',
                                      {'nonblocking': True}))['result']
    assert len(verinfo) == NUM_VALUES_VERINFO

    sigABC2 = jade.jade.make_rpc_call(getsig)['result']
    assert sigABC2 == sigABC1

    wait(1)  # short delay to ensure return to idle status
    jade_is_busy = jade.jade.make_rpc_call(jade.jade.build_request('pingAGAIN', 'ping'))['result']
    assert jade_is_busy == 0  # idle
