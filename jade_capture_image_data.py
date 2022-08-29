#!/usr/bin/env python

import sys
import time
import logging
from jadepy import JadeAPI

LOGGING = logging.INFO
QR = True

# Enable jade logging
if LOGGING:
    jadehandler = logging.StreamHandler()
    jadehandler.setLevel(LOGGING)

    logger = logging.getLogger('jade')
    logger.setLevel(LOGGING)
    logger.addHandler(jadehandler)

    device_logger = logging.getLogger('jade-device')
    device_logger.setLevel(LOGGING)
    device_logger.addHandler(jadehandler)


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

print("Connecting...")
with create_jade_fn(**kwargs) as jade:
    try:
        verinfo = jade.get_version_info()
        print(f'Connected: {verinfo}')

        image_data = jade.capture_image_data(check_qr=QR)
        assert image_data

        with open('capture.dat', 'wb') as f:
            f.write(image_data)

    except Exception as e:
        print("ERROR:", repr(e))
