
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError

from jose.backends.ecdsa_backend import ECDSAECKey
from jose.backends.cryptography_backend import CryptographyECKey

import ecdsa
import pytest

private_key = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIAK499svJugZZfsTsgL2tc7kH/CpzQbkr4g55CEWQyPoAcGBSuBBAAK
oUQDQgAEsOnVqWVPfjte2nI0Ay3oTZVehCUtH66nJM8z6flUluHxhLG8ZTTCkJAZ
W6xQdXHfqGUy3Dx40NDhgTaM8xAdSw==
-----END EC PRIVATE KEY-----"""


class TestECAlgorithm:

    def test_EC_key(self):
        key = ecdsa.SigningKey.from_pem(private_key)
        ECDSAECKey(key, ALGORITHMS.ES256)
        CryptographyECKey(key, ALGORITHMS.ES256)

        ECDSAECKey(private_key, ALGORITHMS.ES256)
        CryptographyECKey(private_key, ALGORITHMS.ES256)

    def test_string_secret(self):
        key = 'secret'
        with pytest.raises(JOSEError):
            ECDSAECKey(key, ALGORITHMS.ES256)

        with pytest.raises(JOSEError):
            CryptographyECKey(key, ALGORITHMS.ES256)

    def test_object(self):
        key = object()
        with pytest.raises(JOSEError):
            ECDSAECKey(key, ALGORITHMS.ES256)

        with pytest.raises(JOSEError):
            CryptographyECKey(key, ALGORITHMS.ES256)
