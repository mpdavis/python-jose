
from jose.algorithms import base

import pytest


@pytest.fixture
def alg():
    return base.Algorithm()


class TestBaseAlgorithm:

    def test_prepare_key_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.prepare_key('secret')

    def test_sign_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.sign('msg', 'secret')

    def test_verify_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.verify('msg', 'secret', 'sig')
