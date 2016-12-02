
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError
from jose.jwk import ECKey

import ecdsa
import pytest

private_key = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIAK499svJugZZfsTsgL2tc7kH/CpzQbkr4g55CEWQyPoAcGBSuBBAAK
oUQDQgAEsOnVqWVPfjte2nI0Ay3oTZVehCUtH66nJM8z6flUluHxhLG8ZTTCkJAZ
W6xQdXHfqGUy3Dx40NDhgTaM8xAdSw==
-----END EC PRIVATE KEY-----"""


class TestECAlgorithm:

    def test_EC_key(self):
        ECKey(private_key, ALGORITHMS.ES256)

    def test_string_secret(self):
        key = 'secret'
        with pytest.raises(JOSEError):
            ECKey(key, ALGORITHMS.ES256)

    def test_object(self):
        key = object()
        with pytest.raises(JOSEError):
            ECKey(key, ALGORITHMS.ES256)
