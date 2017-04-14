
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError
from jose.backends.cryptography_backend import CryptographyECKey
from jose.backends.ecdsa_backend import ECDSAECKey

import ecdsa
import pytest

private_key = b"""-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIAK499svJugZZfsTsgL2tc7kH/CpzQbkr4g55CEWQyPoAcGBSuBBAAK
oUQDQgAEsOnVqWVPfjte2nI0Ay3oTZVehCUtH66nJM8z6flUluHxhLG8ZTTCkJAZ
W6xQdXHfqGUy3Dx40NDhgTaM8xAdSw==
-----END EC PRIVATE KEY-----"""


class TestCryptographyECAlgorithm:

    def test_EC_key(self):
        key = ecdsa.SigningKey.from_pem(private_key)
        k = CryptographyECKey(key, ALGORITHMS.ES256)

        assert k.to_pem().strip() == private_key.strip()
        public_pem = k.public_key().to_pem()
        public_key = CryptographyECKey(public_pem, ALGORITHMS.ES256)

    def test_string_secret(self):
        key = 'secret'
        with pytest.raises(JOSEError):
            CryptographyECKey(key, ALGORITHMS.ES256)

    def test_object(self):
        key = object()
        with pytest.raises(JOSEError):
            CryptographyECKey(key, ALGORITHMS.ES256)

    def test_cryptography_EC_key(self):
        key = ecdsa.SigningKey.from_pem(private_key)
        CryptographyECKey(key, ALGORITHMS.ES256)

    def test_signing_parity(self):
        key1 = ECDSAECKey(private_key, ALGORITHMS.ES256)
        public_key = key1.public_key().to_pem()
        vkey1 = ECDSAECKey(public_key, ALGORITHMS.ES256)
        key2 = CryptographyECKey(private_key, ALGORITHMS.ES256)
        vkey2 = CryptographyECKey(public_key, ALGORITHMS.ES256)

        msg = b'test'
        sig1 = key1.sign(msg)
        sig2 = key2.sign(msg)

        assert vkey1.verify(msg, sig1)
        assert vkey1.verify(msg, sig2)
        assert vkey2.verify(msg, sig1)
        assert vkey2.verify(msg, sig2)

        # invalid signature
        assert not vkey2.verify(msg, b'n' * 64)
