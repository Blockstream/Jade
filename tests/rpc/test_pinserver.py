from . import *
from pinserver.server import PINServerECDHv2
from pinserver.pindb import PINDb


# Pinserver prod defaults
PINSERVER_DEFAULT_URL = 'https://j8d.io'
PINSERVER_DEFAULT_ONION = 'http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion'
# The pubkey for the test (in-proc) pinserver
PINSERVER_TEST_PUBKEY_FILE = 'server_public_key.pub'


def test_set_pinserver(jade):
    """ Update pinserver details - just check the calls do not error"""
    # See test_handshake() above for more in-depth test of this functionality
    with open(PINSERVER_TEST_PUBKEY_FILE, 'rb') as f:
        pubkey = f.read()
    rslt = jade.set_pinserver('https://192.168.0.123:8080',
                              'http://somelongstringblahblahblah.onion',
                              pubkey,
                              'testcertalsoshouldreallybeprettylong')
    assert rslt
    rslt = jade.reset_pinserver(True, True)
    assert rslt


@pytest.mark.mnemonic(mnemonics.invalidatecache)
def test_handshake(jade):
    """
    Pinserver handshake test - note this is tightly coupled to the dedicated
    test handler in the hardware code (main/process/debug_handshake.c)
    """
    # Reset the jade
    rslt = jade.clean_reset()
    assert rslt is True
    get_jade_config().current_mnemonic = None
    # First override the hww pinserver pubkey to match the local test key
    TEST_URL = 'https://this.is.a.test.url.com'
    TEST_ONION = 'http://we.dont.know.our.onion.but.this.string.is.about.the.right.size'
    TEST_CERT = 'tstcert.'*250  # ~2k should be representative of cert size
    with open(PINSERVER_TEST_PUBKEY_FILE, 'rb') as f:
        pubkey = f.read()
    msg = jade.jade.build_request('dbg_pnsvr', 'update_pinserver',
                                  {'urlA': TEST_URL,
                                   'urlB': TEST_ONION,
                                   'pubkey': pubkey,
                                   'certificate': TEST_CERT})
    reply = jade.jade.make_rpc_call(msg)
    assert reply['result'] is True

    # Pin Protocol v2
    # Client provides server with a random ephemeral public key (ske) and a replay counter.
    # This counter serves two purposes - a) it is used to 'tweak' the server static
    # key to generate a determinisitic server ephemeral key (ske), and also it must increase
    # with every request (get and set) for the given client, to prevent message replay.
    # The client also provides an encrypted (and hmaced) and signed piece of data that
    # provides the server with the actual request, to either
    # a) setup a PIN (pubkey, pinsecret) -> aes key entropy mapping (the aes key is random,
    # hmac'd with some 32 byte random from the client and some 32 from the server), or
    # b) fetch the aes key entropy given the (pubkey, pinsecret)
    PINServerECDHv2.load_private_key()

    # A: a test of 'set-pin' (ie. after user has initialised with a mnemonic)

    # 1. trigger the dedicated test case handler
    #    it should test 'set pin' first
    msg = jade.jade.build_request('debugA1', 'debug_handshake')
    reply = jade.jade.make_rpc_call(msg)
    result = reply['result']
    assert list(result.keys()) == ['http_request'], result.keys()
    assert list(result['http_request'].keys()) == ['params', 'on-reply']
    assert result['http_request']['on-reply'] == 'pin'

    assert list(result['http_request']['params'].keys()) == \
        ['urls', 'root_certificates', 'method', 'accept', 'data']
    assert result['http_request']['params']['accept'] == 'json'
    assert result['http_request']['params']['method'] == 'POST'
    urls = result['http_request']['params']['urls']
    assert urls == [TEST_URL+'/set_pin', TEST_ONION+'/set_pin']
    certs = result['http_request']['params']['root_certificates']
    assert certs == [TEST_CERT], f'{certs}'

    # 2. This is where the app would call the URL returned with the data
    #    provided.  We use the pinserver class directly here.
    data = result['http_request']['params']['data']
    data = base64.b64decode(data['data'].encode())
    assert len(data) > 33 + 4

    cke = data[:33]
    replay_counter = data[33:33 + 4]
    encrypted_data = data[33 + 4:]

    server = PINServerECDHv2(replay_counter, cke)
    encrypted_key = server.call_with_payload(cke, encrypted_data, PINDb.set_pin)
    encrypted = base64.b64encode(encrypted_key).decode()

    # 3. Pass the response (encrypted server aes-key) to jade.
    msg2 = jade.jade.build_request(
                         'completeA2', result['http_request']['on-reply'],
                         {'data': encrypted})
    reply2 = jade.jade.make_rpc_call(msg2)
    assert reply2['result'] is True

    # B: a test of 'get-pin' (ie. normal log-in)
    #    The hw test handler will verify that the fetched pin/key data
    #    matches that that was set in A: above.

    # We go through the same steps as above.

    # 1. initiate, get initial url
    msg = jade.jade.build_request('debugB1', 'debug_handshake')
    reply = jade.jade.make_rpc_call(msg)
    result = reply['result']
    assert list(result.keys()) == ['http_request'], result.keys()
    assert list(result['http_request'].keys()) == ['params', 'on-reply']
    assert result['http_request']['on-reply'] == 'pin'
    assert list(result['http_request']['params'].keys()) == \
        ['urls', 'root_certificates', 'method', 'accept', 'data']
    assert result['http_request']['params']['accept'] == 'json'
    assert result['http_request']['params']['method'] == 'POST'
    urls = result['http_request']['params']['urls']
    assert urls == [TEST_URL+'/get_pin', TEST_ONION+'/get_pin']
    certs = result['http_request']['params']['root_certificates']
    assert certs == [TEST_CERT]

    # 2. This is where the app would call the URL returned with the data
    #    provided.  We use the pinserver class directly here.
    # Note: PINServerECDH instances are ephemeral, so we create a new one
    #       here, as that is what would happen in pinserver proper.
    data = result['http_request']['params']['data']
    data = base64.b64decode(data['data'].encode())
    assert len(data) > 33 + 4

    cke = data[:33]
    replay_counter = data[33:33 + 4]
    encrypted_data = data[33 + 4:]

    server = PINServerECDHv2(replay_counter, cke)
    encrypted_key = server.call_with_payload(cke, encrypted_data, PINDb.get_aes_key)
    encrypted = base64.b64encode(encrypted_key).decode()

    # 3. Pass the response (encrypted server aes-key) to jade.
    msg2 = jade.jade.build_request(
                         'completeB2', result['http_request']['on-reply'],
                         {'data': encrypted})
    reply2 = jade.jade.make_rpc_call(msg2)
    assert reply2['result'] is True


@pytest.mark.mnemonic(mnemonics.invalidatecache)
def test_handshake_bad_server(jade):
    """
    Pinserver handshake test - set the hww back to the default/production
    authentication data - this should then fail with 'bad-sig' when we sign
    with the test pinserver details.
    More a test of pinserver than Jade itself, but seems nice to have it here.
    """
    # Load test server keys
    PINServerECDHv2.load_private_key()

    # 1. reset hww back to default pinserver details
    msg = jade.jade.build_request('reset_pnsvr', 'update_pinserver',
                                  {'reset_details': True, 'reset_certificate': True})
    reply = jade.jade.make_rpc_call(msg)
    assert reply['result'] is True

    # 2. trigger the dedicated test case handler - check details are defaults
    msg = jade.jade.build_request('badsig_start', 'debug_handshake')
    reply = jade.jade.make_rpc_call(msg)
    result = reply['result']
    urls = result['http_request']['params']['urls']
    assert urls == [PINSERVER_DEFAULT_URL+'/set_pin',
                    PINSERVER_DEFAULT_ONION+'/set_pin']

    # By default no certificate is returned
    assert 'root_certificates' not in result['http_request']['params']

    # 3. This is where the app would call the URL returned with the data
    #    provided.  We use the pinserver class directly here.
    # We expect this to fail as the ephemeral server key used on each side would not match
    data = result['http_request']['params']['data']
    data = base64.b64decode(data['data'].encode())
    assert len(data) > 33 + 4

    cke = data[:33]
    replay_counter = data[33:33 + 4]
    encrypted_data = data[33 + 4:]

    server = PINServerECDHv2(replay_counter, cke)
    try:
        server.call_with_payload(cke, encrypted_data, PINDb.set_pin)
        assert False, 'Expected exception from bad pinserver'
    except ValueError as e:
        assert str(e) == 'Invalid argument'

    server = PINServerECDHv2(replay_counter, cke)
    try:
        server.call_with_payload(cke, encrypted_data, PINDb.get_aes_key)
        assert False, 'Expected exception from bad pinserver'
    except ValueError as e:
        assert str(e) == 'Invalid argument'

    # Jade should error if sent this empty body (but completes the test case handler)
    msg2 = jade.jade.build_request('completeBad', result['http_request']['on-reply'])
    reply2 = jade.jade.make_rpc_call(msg2)
    assert 'result' not in reply2
    assert 'error' in reply2
    assert reply2['error']['message'] == 'Failed to read parameters from Oracle'
