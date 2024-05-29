"""Test the default import handling."""

try:
    from jose.backends.rsa_backend import RSAKey as PurePythonRSAKey
except ImportError:
    PurePythonRSAKey = None
try:
    from jose.backends.cryptography_backend import CryptographyECKey, CryptographyRSAKey
except ImportError:
    CryptographyRSAKey = CryptographyECKey = None
try:
    from jose.backends.ecdsa_backend import ECDSAECKey as PurePythonECDSAKey
except ImportError:
    PurePythonRSAKey = None

try:
    from jose.backends.cryptography_backend import CryptographyAESKey
except ImportError:
    CryptographyAESKey = None
try:
    from jose.backends.cryptography_backend import CryptographyHMACKey
except ImportError:
    CryptographyHMACKey = None

from jose.backends import ECKey, HMACKey, RSAKey
from jose.backends.native import HMACKey as NativeHMACKey

try:
    from jose.backends import AESKey
except ImportError:
    AESKey = None


def test_default_ec_backend():
    if CryptographyECKey is not None:
        assert ECKey is CryptographyECKey
    else:
        assert ECKey is PurePythonECDSAKey


def test_default_rsa_backend():
    if CryptographyRSAKey is not None:
        assert RSAKey is CryptographyRSAKey
    else:
        assert RSAKey is PurePythonRSAKey


def test_default_aes_backend():
    if CryptographyAESKey is not None:
        assert AESKey is CryptographyAESKey
    else:
        assert AESKey is None


def test_default_hmac_backend():
    if CryptographyHMACKey is not None:
        assert HMACKey is CryptographyHMACKey
    else:
        assert HMACKey is NativeHMACKey
