
# from jose.jwk import Key
# from jose.exceptions import JOSEError

# import pytest


# @pytest.fixture
# def alg():
#     return Key()


# class TestBaseAlgorithm:

#     def test_prepare_key_is_interface(self, alg):
#         with pytest.raises(JOSEError):
#             alg.prepare_key('secret')

#     def test_sign_is_interface(self, alg):
#         with pytest.raises(JOSEError):
#             alg.sign('msg', 'secret')

#     def test_verify_is_interface(self, alg):
#         with pytest.raises(JOSEError):
#             alg.verify('msg', 'secret', 'sig')
