from setuptools import setup

setup(
    name='jadepy',
    version='0.1',
    packages=[
        'jadepy'
    ],
    install_requires=[
        'cbor==1.0.0'
        'pyserial==3.4',
        'bleak==0.5.0',
        'aioitertools==0.4.0'
        'requests==2.22.0'
    ],
)
