from setuptools import setup

setup(
    name='jadepy',
    version='0.2.0',
    packages=[
        'jadepy'
    ],
    install_requires=[
        'cbor>=1.0.0,<2.0.0',
        'pyserial>=3.5.0,<4.0.0'
    ],
    extras_require={
        'ble': [
            'bleak==0.13.0',
            'aioitertools==0.8.0'
        ],
        'requests': [
            'requests>=2.26.0,<3.0.0'
        ]
    }
)
