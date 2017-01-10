
from jose.jwk import Key, HMACKey, RSAKey, ECKey
from jose.constants import ALGORITHMS

import pytest


@pytest.fixture
def alg():
    return Key("key", "ALG")


class TestBaseAlgorithm:

    def test_sign_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.sign('msg')

    def test_verify_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.verify('msg', 'sig')


class TestAlgorithms:

    def test_get_key(self):
        assert ALGORITHMS.get_key("HS256") == HMACKey
        assert ALGORITHMS.get_key("RS256") == RSAKey
        assert ALGORITHMS.get_key("ES256") == ECKey

        assert ALGORITHMS.get_key("NONEXISTENT") == None
    
    def test_register_key(self):
        assert ALGORITHMS.register_key("ALG", Key) == True
        assert ALGORITHMS.get_key("ALG") == Key

        assert ALGORITHMS.register_key("ALG", object) == False
