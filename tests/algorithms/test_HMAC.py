
from jose.jwk import HMACKey
from jose.exceptions import JOSEError

import pytest


@pytest.fixture
def alg():
    return HMACKey(HMACKey.SHA256)


class TestHMACAlgorithm:

    def test_non_string_key(self, alg):
        with pytest.raises(JOSEError):
            alg.prepare_key(object())

    def test_RSA_key(self, alg):
        key = "-----BEGIN PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            alg.prepare_key(key)
