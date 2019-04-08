"""Test the default import handling."""
try:
    from jose.backends.rsa_backend import RSAKey as PurePythonRSAKey
except ImportError:
    PurePythonRSAKey = None
try:
    from jose.backends.cryptography_backend import CryptographyRSAKey, CryptographyECKey
except ImportError:
    CryptographyRSAKey = CryptographyECKey = None
try:
    from jose.backends.pycrypto_backend import RSAKey as PyCryptoRSAKey
except ImportError:
    PyCryptoRSAKey = None
try:
    from jose.backends.ecdsa_backend import ECDSAECKey as PurePythonECDSAKey
except ImportError:
    PurePythonRSAKey = None

from jose.backends import ECKey, RSAKey


def test_default_ec_backend():
    if CryptographyECKey is not None:
        assert ECKey is CryptographyECKey
    else:
        assert ECKey is PurePythonECDSAKey


def test_default_rsa_backend():
    if CryptographyRSAKey is not None:
        assert RSAKey is CryptographyRSAKey
    elif PyCryptoRSAKey is not None:
        assert RSAKey is PyCryptoRSAKey
    else:
        assert RSAKey is PurePythonRSAKey
