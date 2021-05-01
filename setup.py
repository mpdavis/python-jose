#!/usr/bin/env python
import os
from pathlib import Path

import jose  # noqa: F401

from setuptools import setup


long_description = (Path(__file__) / 'README.rst').read_text()


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [
        dirpath
        for dirpath, dirnames, filenames in os.walk(package)
        if os.path.exists(os.path.join(dirpath, '__init__.py'))
    ]


pyasn1 = ['pyasn1']
extras_require = {
    'cryptography': ['cryptography'],
    'pycrypto': ['pycrypto >=2.6.0, <2.7.0'] + pyasn1,
    'pycryptodome': ['pycryptodome >=3.3.1, <4.0.0'] + pyasn1,
}
legacy_backend_requires = ['ecdsa != 0.15', 'rsa'] + pyasn1
install_requires = ['six <2.0']

# TODO: work this into the extras selection instead.
install_requires += legacy_backend_requires


setup(
    name='python-jose',
    author='Michael Davis',
    author_email='mike.philip.davis@gmail.com',
    description='JOSE implementation in Python',
    license='MIT',
    keywords='jose jws jwe jwt json web token security signing',
    url='http://github.com/mpdavis/python-jose',
    packages=get_packages('jose'),
    long_description=long_description,
    project_urls={
        'Documentation': 'https://python-jose.readthedocs.io/en/latest/',
        'Source': 'http://github.com/mpdavis/python-jose/',
        'Tracker': 'http://github.com/mpdavis/python-jose/issues/',
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Utilities',
    ],
    extras_require=extras_require,
    setup_requires=[
        'pytest-runner',
        'setuptools>=39.2.0',
    ],
    tests_require=[
        'six',
        'ecdsa != 0.15',
        'pytest',
        'pytest-cov',
        'pytest-runner',
    ],
    install_requires=install_requires
)
