#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import platform

import jose

from setuptools import setup


with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    long_description = readme.read()


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [
        dirpath
        for dirpath, dirnames, filenames in os.walk(package)
        if os.path.exists(os.path.join(dirpath, '__init__.py'))
    ]


def _cryptography_version():
    # pyca/cryptography dropped support for PyPy < 5.4 in 2.5
    # https://cryptography.io/en/latest/changelog/#v2-5
    if platform.python_implementation() == 'PyPy' and platform.python_version() < '5.4':
        return 'cryptography < 2.5'

    return 'cryptography'


pyasn1 = ['pyasn1']
extras_require = {
    'cryptography': [_cryptography_version()],
    'pycrypto': ['pycrypto >=2.6.0, <2.7.0'] + pyasn1,
    'pycryptodome': ['pycryptodome >=3.3.1, <4.0.0'] + pyasn1,
}
legacy_backend_requires = ['ecdsa <1.0', 'rsa'] + pyasn1
install_requires = ['six <2.0']

# TODO: work this into the extras selection instead.
install_requires += legacy_backend_requires


setup(
    name='python-jose',
    version=jose.__version__,
    author='Michael Davis',
    author_email='mike.philip.davis@gmail.com',
    description='JOSE implementation in Python',
    license='MIT',
    keywords='jose jws jwe jwt json web token security signing',
    url='http://github.com/mpdavis/python-jose',
    packages=get_packages('jose'),
    long_description=long_description,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Utilities',
    ],
    extras_require=extras_require,
    setup_requires=['pytest-runner'],
    tests_require=[
        'six',
        'ecdsa',
        'pytest',
        'pytest-cov',
        'pytest-runner',
    ],
    install_requires=install_requires
)
