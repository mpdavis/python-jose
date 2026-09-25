"""Test the default import handling."""

from jose.backends import AESKey, ECKey, HMACKey, RSAKey
from jose.backends.cryptography_backend import (
    CryptographyAESKey,
    CryptographyECKey,
    CryptographyHMACKey,
    CryptographyRSAKey,
)


def test_default_ec_backend():
    assert ECKey is CryptographyECKey


def test_default_rsa_backend():
    assert RSAKey is CryptographyRSAKey


def test_default_aes_backend():
    assert AESKey is CryptographyAESKey


def test_default_hmac_backend():
    assert HMACKey is CryptographyHMACKey
