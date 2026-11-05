from . import *


def test_hotp(jade):
    """Test according to otp spec (rfc6238)"""
    hotp_name = 'test_hotp'
    hotp_uri = 'otpauth://hotp/ACME%20Co:john.doe@email.com\
?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&counter={}'

    # Register HOTP record
    rslt = jade.register_otp(hotp_name, hotp_uri.format(0))
    assert rslt

    expected_results = ['755224', '287082', '359152', '969429', '338314',
                        '254676', '287922', '162583', '399871', '520489']

    # Fetch repeated codes 'naturally'
    for expected in expected_results:
        rslt = jade.get_otp_code(hotp_name)
        assert rslt == expected

    # Fetch repeated codes explicitly passing the counter
    for i, expected in enumerate(expected_results):
        rslt = jade.get_otp_code(hotp_name, value_override=i)
        assert rslt == expected

    # Check can register with an 'initial counter' - eg. starting from 5
    startfrom = 5
    rslt = jade.register_otp(hotp_name, hotp_uri.format(startfrom))
    assert rslt

    # Fetch repeated codes 'naturally' from the explicit start point
    for expected in expected_results[startfrom:]:
        rslt = jade.get_otp_code(hotp_name)
        assert rslt == expected

    if transport_is_not('libjade'):
        return  # Only test bad parameters on libjade

    # Test bad uri parameters
    hotp_uri = '&'.join(hotp_uri.split('&')[:-1])
    bad_params = [
        '',                                # counter not given
        '&counter=',                       # counter empty
        '&counter=000000000000000000001',  # counter too long
        '&counter=18446744073709551616',   # counter too large
        '&counter=abc',                    # counter not a number
    ]
    for params in bad_params:
        try:
            jade.register_otp(hotp_name, hotp_uri + params)
            assert False, f'hotp error not raised for "{params}"'
        except JadeError as err:
            assert err.code == JadeError.BAD_PARAMETERS
            assert 'Failed to parse otp record' in err.message
            continue


def test_totp(jade):
    """Test according to otp spec (rfc6238)"""
    totp_name = 'test_totp'
    totp_uri = 'otpauth://totp/ACME%20Co:john.doe@email.com\
?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&digits=8&algorithm={}'

    timestamps = [59, 1111111109, 1111111111,
                  1234567890, 2000000000, 20000000000]

    expected_results = [
      ('SHA1',
       ('94287082', '07081804', '14050471',
        '89005924', '69279037', '65353130')),
      ('SHA256',
       ('46119246', '68084774', '67062674',
        '91819424', '90698825', '77737706')),
      ('SHA512',
       ('90693936', '25091201', '99943326',
        '93441116', '38618901', '47863826'))
    ]

    for algo, expected in expected_results:
        rslt = jade.register_otp(totp_name, totp_uri.format(algo))
        assert rslt

        # Fetch code 'naturally' - can't verify result but just see that it works
        rslt = jade.get_otp_code(totp_name)
        assert len(rslt) == 8

        # Fetch repeated codes explicitly passing the timestamp
        for i, timestamp in enumerate(timestamps):
            rslt = jade.get_otp_code(totp_name, value_override=timestamp)
            assert rslt == expected[i]

    if transport_is_not('libjade'):
        return  # Only test bad parameters on libjade

    # Test bad uri parameters
    totp_uri = '&'.join(totp_uri.split('&')[:-2])
    bad_params = [
        '&digits=',         # digits not given
        '&digits=7',        # digits not valid (6 or 8)
        '&period=',         # period empty
        '&period=256',      # period too large
        '&z=' + 'A' * 512,  # uri too long
    ]
    for params in bad_params:
        try:
            jade.register_otp(totp_name, totp_uri + params)
            assert False, f'totp error not raised for "{params}"'
        except JadeError as err:
            assert err.code == JadeError.BAD_PARAMETERS
            assert 'Failed to parse otp record' in err.message
            continue


def test_totp_ex(jade):
    # NOTE:
    # There is some uncertainty around secrets padding when shorter than the hash size.
    # rfc6238 test vectors appear to suggest the secrets should be lengthened by repetition to the
    # length of the hash, although gauth-like implementations do not appear to do this - rather
    # they just use the short secret as is.
    # To maintain maximum compatibility we do not lengthen the secret for SHA1 *only*, and we do
    # lengthen short secrets for other hash digest algorithms.
    # This provides compatability with gauth-like services, and should also remain compatible with
    # HOTP/SHA1 which does not extend the secrets.
    # Short secret - not padded/lengthened for SHA1 for maximum gauth compatibility
    totp_name = 'test_totp_ex'
    totp_uri = 'otpauth://totp/ACM?secret=VMR466AB62ZBOKHE&digits=6&algorithm=SHA1'
    rslt = jade.register_otp(totp_name, totp_uri)
    assert rslt

    # Fetch repeated codes explicitly passing the timestamp
    ts_rslt = [(0, '538532'), (1426847216, '543160')]
    for timestamp, expected in ts_rslt:
        rslt = jade.get_otp_code(totp_name, value_override=timestamp)
        assert rslt == expected

    # Short secret - not padded for gauth/SHA1
    totp_name = 'test_totp_ex'
    totp_uri = 'otpauth://totp/Foo?secret=VM'
    rslt = jade.register_otp(totp_name, totp_uri)
    assert rslt

    # Fetch repeated codes explicitly passing the timestamp
    ts_rslt = [(1659641526, '468828'), (1659641674, '550073'), (1659641710, '222948')]
    for timestamp, expected in ts_rslt:
        rslt = jade.get_otp_code(totp_name, value_override=timestamp)
        assert rslt == expected

    # Long secret for SHA512 - padded if required
    totp_name = 'test_totp_ex'
    totp_uri = 'otpauth://totp/Foo\
?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDG\
NBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&digits=8&algorithm=SHA512'
    rslt = jade.register_otp(totp_name, totp_uri)
    assert rslt

    # Fetch repeated codes explicitly passing the timestamp
    ts_rslt = [(59, '90693936'),
               (1111111109, '25091201'),
               (1111111111, '99943326'),
               (1234567890, '93441116'),
               (2000000000, '38618901'),
               (20000000000, '47863826')]
    for timestamp, expected in ts_rslt:
        rslt = jade.get_otp_code(totp_name, value_override=timestamp)
        assert rslt == expected
