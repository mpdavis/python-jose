
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

    def test_register_key(self):
        assert ALGORITHMS.register_key("ALG", Key)
        from jose.jwk import get_key
        assert get_key("ALG") == Key
    
        with pytest.raises(TypeError):
            assert ALGORITHMS.register_key("ALG", object)
