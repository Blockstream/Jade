from setuptools import setup

setup(
    name='jadepy',
    version='0.1',
    packages=[
        'jadepy'
    ],
    install_requires=[
        'pyserial==3.4',
        'bleak==0.5.0',
        'aioitertools==0.4.0'
    ],
)
