
from jose.algorithms import HMACAlgorithm
from jose.exceptions import JOSEError

import pytest


@pytest.fixture
def alg():
    return HMACAlgorithm(HMACAlgorithm.SHA256)


class TestHMACAlgorithm:

    def test_non_string_key(self, alg):
        with pytest.raises(JOSEError):
            alg.prepare_key(object())

    def test_unicode_encode(self, alg):
        key = u'secret'
        prepared_key = alg.prepare_key(key)
        assert key == prepared_key

    def test_RSA_key(self, alg):
        key = "-----BEGIN PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            alg.prepare_key(key)
