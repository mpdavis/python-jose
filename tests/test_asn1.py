"""Tests for ``jose.backends._asn1``."""
import base64

import pytest

try:
    from jose.backends import _asn1
except ImportError:
    _asn1 = None

from .algorithms.test_RSA import PKCS1_PRIVATE_KEY, PKCS8_PRIVATE_KEY

pytestmark = [
    pytest.mark.pycrypto,
    pytest.mark.pycryptodome,
    pytest.mark.skipif(_asn1 is None, reason="ASN1 backend not available")
]


def test_rsa_private_key_pkcs1_to_pkcs8():
    pkcs1 = base64.b64decode(PKCS1_PRIVATE_KEY)
    pkcs8 = base64.b64decode(PKCS8_PRIVATE_KEY)

    assert _asn1.rsa_private_key_pkcs1_to_pkcs8(pkcs1) == pkcs8


def test_rsa_private_key_pkcs8_to_pkcs1():
    pkcs1 = base64.b64decode(PKCS1_PRIVATE_KEY)
    pkcs8 = base64.b64decode(PKCS8_PRIVATE_KEY)

    assert _asn1.rsa_private_key_pkcs8_to_pkcs1(pkcs8) == pkcs1
