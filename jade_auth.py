#!/usr/bin/env python

import sys
import logging
from jadepy import JadeAPI, JadeError

LOGGING = True

# We can test with the gdk http_request() function if we have the wheel installed
# The default is to use the simple built-in http requests client.
USE_GDK_HTTP_CLIENT = False

# script to test user auth and pinserver interaction
# need to run the pinserver as in docker as described in its readme
# (or directly with flask run)

# Enable jade logging
if LOGGING:
    jadehandler = logging.StreamHandler()
    jadehandler.setLevel(logging.INFO)

    logger = logging.getLogger('jadepy.jade')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(jadehandler)

    logger = logging.getLogger('jadepy.jade-device')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(jadehandler)


# We can test with the gdk http_request() function if we have the wheel installed
http_request_fn = None
if USE_GDK_HTTP_CLIENT:
    import json
    import greenaddress as gdk

    gdk.init({})
    gdk_session = gdk.Session({'name': 'mainnet'})

    def http_request_fn(params):
        reply = gdk.http_request(gdk_session.session_obj, json.dumps(params))
        return json.loads(reply)


if len(sys.argv) > 1 and sys.argv[1] == 'ble':
    print('Fetching jade version info over BLE')
    serial_number = sys.argv[2] if len(sys.argv) > 2 else None
    create_jade_fn = JadeAPI.create_ble
    kwargs = {'serial_number': serial_number}
else:
    print('Fetching jade version info over serial')
    serial_device = sys.argv[1] if len(sys.argv) > 1 else None
    create_jade_fn = JadeAPI.create_serial
    kwargs = {'device': serial_device, 'timeout': 120}

print('Connecting...')
with create_jade_fn(**kwargs) as jade:
    verinfo = jade.get_version_info()
    print(f'Connected: {verinfo}')

    # Tell Jade to auth the user on the hw
    # Note: this requires a pinserver to be running
    # The network to use is deduced from the version-info
    network = 'testnet' if verinfo.get('JADE_NETWORKS') == 'TEST' else 'mainnet'
    try:
        while jade.auth_user(network, http_request_fn) is not True:
            print('Error - please try again')
    except JadeError as e:
        if e.code == JadeError.USER_CANCELLED:
            print('User abandoned PIN entry')
            network = None
        else:
            raise

    if network:
        # Just a couple of test calls that mimic what gdk-logon does
        print(jade.get_xpub(network, []))
        print(jade.sign_message([1195487518], 'greenaddress.it      login ABCDE'))
