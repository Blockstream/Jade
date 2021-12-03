from setuptools import setup

setup(
    name='jadepy',
    version='0.1',
    packages=[
        'jadepy'
    ],
    install_requires=[
        'cbor==1.0.0',
        'pyserial==3.5',
        'bleak==0.13.0',
        'aioitertools==0.8.0',
        'requests==2.26.0'
    ],
)
