from . import *


@with_test_cases('tests/rpc/data/scan_qr/qr_qvga_*.json')
def test_scan_qr(jade, test_case):
    """
    Test qr scanning - can be slow as image data large (slow to upload) and
    tests involve starting the camera (and associated tasks).
    """
    # Only run QR scan/camera tests over serial/libjade on camera-capable Jade hardware.
    config = get_jade_config()
    if config.transport not in ['serial', 'libjade']:
        pytest.skip('QR scan/camera tests require serial or libjade transport')

    if (
        config.transport == 'serial'
        and config.version_info['BOARD_TYPE'] not in ['JADE', 'JADE_V1.1', 'JADE_V2']
    ):
        pytest.skip('QR scan/camera tests require camera-capable Jade hardware')

    expected = test_case['expected_output']
    image_filename = test_case['input']['image']
    with open('tests/rpc/data/scan_qr/' + image_filename, 'rb') as f:
        image_data = f.read()

    rslt = jade.scan_qr(image_data)
    assert rslt

    if expected.get('text') is not None:
        assert rslt.decode() == expected['text']
    else:
        assert rslt == expected['hex']

    # Reset the epoch time for any following tests
    jade.set_epoch(int(time.time()))
