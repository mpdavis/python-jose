import pytest

from jose.jwk import Key


@pytest.fixture
def alg():
    return Key("key", "ALG")


class TestBaseAlgorithm:
    def test_sign_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.sign("msg")

    def test_verify_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.verify("msg", "sig")

    def test_encrypt_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.encrypt(
                "plain text",
            )

    def test_decrypt_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.decrypt("plain text", iv="iv")

    def test_wrap_key_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.wrap_key("plain text")

    def test_unwrap_key_is_interface(self, alg):
        with pytest.raises(NotImplementedError):
            alg.unwrap_key("plain text")
