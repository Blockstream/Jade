from setuptools import setup

# Extract the jadepy version
version = open('jadepy/__init__.py').readlines()
version = [v for v in version if '__version__' in v][0].strip()
version = version.split('"')[-2]
assert len(version.split('.')) == 3, f'Invalid parsed version "{version}"'

setup(
    name='jade_client',
    version=version,
    description='Blockstream Jade Client API',
    long_description='A Python library for interacting with the Blockstream Jade hardware wallet',
    url='https://github.com/Blockstream/Jade',
    author='Blockstream',
    author_email='inquiries@blockstream.com',
    license_expression='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'Programming Language :: Python :: 3',
    ],
    keywords=[
        'Blockstream',
        'Jade',
        'Hardware wallet',
        'Bitcoin',
        'BTC'
        'Liquid',
    ],
    project_urls={
        'Documentation': 'https://github.com/Blockstream/Jade/README.md',
        'Source': 'https://github.com/Blockstream/Jade',
        'Tracker': 'https://github.com/Blockstream/Jade/issues',
    },
    packages=[
        'jadepy'
    ],
    install_requires=[
        'cbor2>=5.4.6,<6.0.0',
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
