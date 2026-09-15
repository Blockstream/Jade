import cbor2 as cbor
import random
from . import *
from .. import _get_test_cases


LIQUID_DESCRIPTORS = True

# Time to wait for stale data timeout on device before sending follow-up message.
# The firmware stale-data timeout (wire.c TIMEOUT_TICKS) is 3s on v1.x and 2s on v2.x.
# This value must be > TIMEOUT_TICKS to reliably trigger the stale path.
STALE_DATA_TIMEOUT = 4

NUM_VALUES_VERINFO = 22

LOW_LEVEL_VECTORS = next(_get_test_cases('tests/rpc/data/low_level/bad_params.json'))[0]
LOW_LEVEL_LIQUID_VECTORS = next(_get_test_cases(
    'tests/rpc/data/low_level/bad_params_liquid.json'))[0]
TEST_SCRIPT = LOW_LEVEL_VECTORS['TEST_SCRIPT']
TEST_THEIR_PK = LOW_LEVEL_VECTORS['TEST_THEIR_PK']
TEST_HASH_PREVOUTS = LOW_LEVEL_VECTORS['TEST_HASH_PREVOUTS']
TEST_REGTEST_BITCOIN = LOW_LEVEL_VECTORS['TEST_REGTEST_BITCOIN']
EXPECTED_MASTER_BLINDING_KEY = LOW_LEVEL_VECTORS['EXPECTED_MASTER_BLINDING_KEY']
EXPECTED_BLINDING_KEY = LOW_LEVEL_VECTORS['EXPECTED_BLINDING_KEY']
EXPECTED_LIQ_COMMITMENT_1 = LOW_LEVEL_VECTORS['EXPECTED_LIQ_COMMITMENT_1']
EXPECTED_LIQ_COMMITMENT_2 = LOW_LEVEL_VECTORS['EXPECTED_LIQ_COMMITMENT_2']


def _test_good_params(jade, rpc_args):
    request = jade.build_request(*rpc_args)
    reply = jade.make_rpc_call(request)

    # Assert all-good response
    assert reply['id'] == request['id']
    assert 'error' not in reply
    assert 'result' in reply
    return reply['result']


def test_bad_message(jade):
    bad_requests = [{'method': 'get_version_info'},  # no-id
                    {'id': '2'},               # no method
                    {'id': 123},               # bad id type
                    {'id': '12345'*8},         # id too long
                    {'method': 'x'*40, 'id': '4'}]   # method

    for request in bad_requests:
        msgbytes = cbor.dumps(request)
        jade.jade.write(msgbytes)

        # Expect one reject message for the bad (but well formed) input
        reply = jade.jade.read_response()

        # Returned id should match sent and valid, or '00' if not
        assert 'id' in reply
        if 'id' in request and \
           isinstance(request['id'], str) and \
           len(request['id']) < 32:
            assert reply['id'] == request['id']  # matches
        else:
            assert reply['id'] == '00'           # default error id

        # Assert bad message response
        assert 'result' not in reply
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'].startswith('Invalid RPC Request message')
        assert int(error['data']) == len(msgbytes)
        assert 'result' not in reply


def test_very_bad_message(jade):
    empty = cbor.dumps(b'')
    text = cbor.dumps('This is not a good cbor message')
    truncated = cbor.dumps("{'id': '1', method: 'msgwillbecut'}")[1:]
    goodmsg = jade.jade.build_request('ent', 'add_entropy', {'entropy': 'noise'.encode()})

    for badmsg in [empty, text, truncated]:
        # Send the bad message, and after a pause a good message
        jade.jade.write(badmsg)
        wait(STALE_DATA_TIMEOUT, force=True)
        jade.jade.write_request(goodmsg)

        # We should receive a bag of errors
        # NOTE: we cannot be sure how many messages will be returned exactly,
        # but we do know that Jade should reject a total of 'len(badmsg)' bytes.
        bad_bytes = 0
        while bad_bytes < len(badmsg):
            reply = jade.jade.read_response()

            # Returned id should be '00'
            assert reply['id'] == '00'
            assert 'result' not in reply

            # Assert bad message response
            error = reply['error']
            assert error['code'] == JadeError.INVALID_REQUEST
            assert error['message'].startswith('Invalid RPC Request message')
            bad_bytes += int(error['data'])

        assert bad_bytes == len(badmsg)

        # After the bad bytes have been rejected, we expect to see the reply to the good message
        reply = jade.jade.read_response()
        assert reply['id'] == 'ent'
        assert 'error' not in reply
        assert 'result' in reply
        assert reply['result'] is True


def test_random_bytes(jade):
    # Stream up 1k of random bytes, then a good message after a short pause
    # NOTE: use fixed pseudo-random here, so test run is reproducible
    random.seed(12345678, 2)
    nsent = 0
    for _ in range(8):
        noise = random.getrandbits(128*8).to_bytes(128, 'little')
        jade.jade.write(noise)
        nsent += len(noise)

    wait(STALE_DATA_TIMEOUT, force=True)
    goodmsg = jade.jade.build_request('goodmsg', 'add_entropy', {'entropy': 'somebytes'.encode()})
    jade.jade.write_request(goodmsg)

    # We should receive a bag of errors
    # NOTE: we cannot be sure how many messages will be returned exactly,
    # but we do know that Jade should reject a total of 'nsent' bytes.
    nreceived = 0
    while nreceived < nsent:
        # Expect error - count rejected bytes
        reply = jade.jade.read_response()
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'].startswith('Invalid RPC Request message')
        nreceived += int(error['data'])

    assert nreceived == nsent

    # After the bad bytes have been rejected, we expect to see the reply to the good message
    reply = jade.jade.read_response()
    assert reply['id'] == 'goodmsg'
    assert 'error' not in reply
    assert 'result' in reply
    assert reply['result'] is True


def test_too_much_input(jade):
    noise = 'long'.encode()   # 4b
    cacophony = noise * 4096  # 16k

    # NOTE: if the hw has PSRAM it will have a 401k buffer.
    # If not, it will have a 17k buffer.  Want only 1k left.
    # Send the appropriate amount of noise. (400k or 16k)
    if get_jade_config().has_psram:
        cacophony = cacophony * 25  # 25x16 is 400k

    # Input buffer would now only have 1k space remaining.
    # Add another 1k to fill the buffer
    cacophony += noise * 256  # 1k
    expected_buffer_size = len(cacophony)

    # Then add another 64b to overflow
    extra = noise * 16  # 64b
    cacophony += extra

    # Format as a cbor message, otherwise it gets rejected early, as soon
    # as the parser decides the bytes it has are not a valid message.
    # See: test_very_bad_message() above.
    big_msg = cbor.dumps({'method': 'toobig', 'id': 'tohandle', 'params': cacophony})
    # Adjust the expected_overflow_len for the cbor overhead
    total_len = len(big_msg)
    expected_overflow_len = total_len - expected_buffer_size

    # Send the message up with 4k writes
    # (otherwise, trying to write too much can hit the timeout)
    remaining = total_len
    while remaining:
        tosend = min(remaining, 4096)
        jade.jade.write(big_msg[total_len - remaining: (total_len - remaining) + tosend])
        remaining -= tosend

    # First we expect to get a response about the buffer-overflow bytes
    # ie. one (initial) reject message with a big number in!
    reply = jade.jade.read_response()
    error = reply['error']
    assert error['code'] == JadeError.INVALID_REQUEST
    assert error['message'].startswith('Invalid RPC Request message')
    assert int(error['data']) == expected_buffer_size

    # After a short pause send a good message
    wait(STALE_DATA_TIMEOUT, force=True)
    goodmsg = jade.jade.build_request('trailer', 'add_entropy', {'entropy': 'random'.encode()})
    jade.jade.write_request(goodmsg)

    # We should then receive a bag of errors
    # NOTE: we cannot be sure how many messages will be returned exactly,
    # but we do know that Jade should reject a total of 'expected_overflow_len' bytes.
    bad_bytes = 0
    while bad_bytes < expected_overflow_len:
        # Expect error - collect bad bytes
        reply = jade.jade.read_response()
        error = reply['error']
        assert error['code'] == JadeError.INVALID_REQUEST
        assert error['message'].startswith('Invalid RPC Request message')
        bad_bytes += int(error['data'])

    assert bad_bytes == expected_overflow_len, f'{bad_bytes} != {expected_overflow_len}'

    # After the bad bytes have been rejected, we expect to see the reply to the good message
    reply = jade.jade.read_response()
    assert reply['id'] == 'trailer'
    assert 'error' not in reply
    assert 'result' in reply
    assert reply['result'] is True


def test_split_message(jade):
    # Simulate transport stream being v.slow
    msg = cbor.dumps({'method': 'get_version_info', 'id': '24680'})
    for msgpart in [msg[:5], msg[5:10], msg[10:]]:
        jade.jade.write(msgpart)
        wait(0.25, force=True)

    reply = jade.jade.read_response()

    # Returned id should match sent
    assert reply['id'] == '24680'
    assert 'error' not in reply
    assert 'result' in reply and len(reply['result']) == NUM_VALUES_VERINFO


@pytest.mark.parametrize('do_wait', [False, True])
def test_concatenated_messages(jade, do_wait):
    # Simulate a 'bad' client sending two messages without waiting for a reply
    msg1 = {'method': 'get_version_info', 'id': '123456'}
    msg2 = {'method': 'get_version_info', 'id': '456789'}
    concat_cbor = cbor.dumps(msg1) + cbor.dumps(msg2)
    # Split the write of the messages in two at a random point
    split_point = random.randint(1, len(concat_cbor) - 1)
    jade.jade.write(concat_cbor[:split_point])
    if do_wait:
        # Force the first write to timeout (become stale)
        wait(STALE_DATA_TIMEOUT, force=True)
    jade.jade.write(concat_cbor[split_point:])

    reply1 = jade.jade.read_response()
    reply2 = jade.jade.read_response()

    # Returned ids should match sent
    for msg, reply in [(msg1, reply1), (msg2, reply2)]:
        assert reply['id'] == msg['id']
        assert 'error' not in reply
        assert 'result' in reply and len(reply['result']) == NUM_VALUES_VERINFO


def test_unknown_method(jade):
    # Includes tests of method prefixes 'get...' and 'sign...'
    for msgid, method in [('unk0', 'dostuff'), ('unk1', 'get'), ('unk2', 'sign'),
                          ('unk3', 'handshake_init')]:
        request = jade.jade.build_request(
            msgid,
            method,
            {'path': (0, 1, 2, 3, 4), 'message': 'Jade is cool'},
        )
        reply = jade.jade.make_rpc_call(request)

        # Returned id should match sent
        assert reply['id'] == msgid

        # Assert unknown method response
        error = reply['error']
        assert error['code'] == JadeError.UNKNOWN_METHOD
        assert error['message'] == 'Unknown method'
        assert 'result' not in reply


def test_unexpected_method(jade):
    # These messages are only expected as a subsequent message
    # in a multi-message protocol.
    unexpected = [('protocol2', 'pin',
                   {'payload': 'abcdef', 'hmac': '1234'}),
                  ('protocol3', 'ota_data', bytes.fromhex('abcdef')),
                  ('protocol4', 'ota_complete'),
                  ('protocol5', 'tx_input'),
                  ('protocol6', 'get_signature'),
                  ('protocol7', 'get_extended_data')]

    for rpc_args in unexpected:
        request = jade.jade.build_request(*rpc_args)
        reply = jade.jade.make_rpc_call(request)

        # Assert protocol-error/unexpected-method response
        error = reply['error']
        assert error['code'] == JadeError.PROTOCOL_ERROR
        assert error['message'] == 'Unexpected method'
        assert 'result' not in reply


def test_bad_params(jade):
    vectors = LOW_LEVEL_VECTORS
    for badmsg, errormsg in vectors['bad_params']:
        if transport_is('libjade') and badmsg[1] in ['ota', 'ota_delta']:
            continue
        check_bad_params(jade.jade, badmsg, errormsg)
    for badinput, errormsg in vectors['bad_tx_inputs']:
        result = _test_good_params(
            jade.jade,
            ('signTx', 'sign_tx',
             {'network': 'localtest', 'txn': vectors['good_tx'],
              'num_inputs': 1}))
        assert result is True
        check_bad_params(jade.jade, badinput, errormsg)


def test_bad_params_liquid(jade):
    vectors = LOW_LEVEL_LIQUID_VECTORS
    for badmsg, errormsg in vectors['bad_params']:
        check_bad_params(jade.jade, badmsg, errormsg)
    for badcommitment, errormsg in vectors['bad_commitments']:
        if not get_jade_config().has_psram and ('asset_blind_proof' in badcommitment or
                                                'value_blind_proof' in badcommitment):
            continue
        check_bad_params(
            jade.jade,
            ('signLiquid', 'sign_liquid_tx',
             {'network': 'localtest-liquid', 'txn': vectors['good_tx'],
              'num_inputs': 1,
              'trusted_commitments': [badcommitment, {}]}),
            errormsg)
    for badinput, errormsg in vectors['bad_liq_inputs']:
        result = _test_good_params(
            jade.jade,
            ('signLiquidInput', 'sign_liquid_tx',
             {'network': 'localtest-liquid', 'txn': vectors['good_tx'],
              'num_inputs': 1,
              'trusted_commitments': vectors['good_commitments']}))
        assert result is True
        check_bad_params(jade.jade, badinput, errormsg)
