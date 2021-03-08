#!/usr/bin/env python
import os
from pathlib import Path

from setuptools import setup

import jose  # noqa: F401

long_description = (Path(__file__).parent / "README.rst").read_text()


def get_packages(package):
    """
    Return root package and all sub-packages.
    """
    return [
        dirpath
        for dirpath, dirnames, filenames in os.walk(package)
        if os.path.exists(os.path.join(dirpath, "__init__.py"))
    ]


pyasn1 = ["pyasn1"]
extras_require = {
    "cryptography": ["cryptography>=3.4.0"],
    "pycrypto": ["pycrypto >=2.6.0, <2.7.0"] + pyasn1,
    "pycryptodome": ["pycryptodome >=3.3.1, <4.0.0"] + pyasn1,
}
# TODO: work this into the extras selection instead.
install_requires = ["ecdsa != 0.15", "rsa"] + pyasn1


setup(
    name="python-jose",
    author="Michael Davis",
    author_email="mike.philip.davis@gmail.com",
    description="JOSE implementation in Python",
    license="MIT",
    keywords="jose jws jwe jwt json web token security signing",
    url="http://github.com/mpdavis/python-jose",
    packages=get_packages("jose"),
    long_description=long_description,
    project_urls={
        "Documentation": "https://python-jose.readthedocs.io/en/latest/",
        "Source": "https://github.com/mpdavis/python-jose/",
        "Tracker": "https://github.com/mpdavis/python-jose/issues/",
        "Changelog": "https://github.com/mpdavis/python-jose/blob/master/CHANGELOG.md",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Utilities",
    ],
    extras_require=extras_require,
    setup_requires=[
        "pytest-runner",
        "setuptools>=39.2.0",
    ],
    tests_require=[
        "ecdsa != 0.15",
        "pytest",
        "pytest-cov",
        "pytest-runner",
    ],
    install_requires=install_requires,
)
