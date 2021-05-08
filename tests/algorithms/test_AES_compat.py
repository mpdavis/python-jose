import pytest

try:
    from jose.backends.cryptography_backend import CryptographyAESKey
except ImportError:
    CryptographyAESKey = None

from jose.constants import ALGORITHMS
from jose.exceptions import JWEError

CRYPTO_BACKENDS = (pytest.param(CryptographyAESKey, id="pyca/cryptography"),)


@pytest.mark.backend_compatibility
@pytest.mark.skipif(
    CryptographyAESKey is None, reason="Multiple crypto backends not available for backend compatibility tests"
)
class TestBackendAesCompatibility:
    @pytest.mark.parametrize("backend_decrypt", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("backend_encrypt", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("algorithm", ALGORITHMS.AES_PSEUDO)
    def test_encryption_parity(self, backend_encrypt, backend_decrypt, algorithm):
        if "128" in algorithm:
            key = b"8slRzzty6dKMaFCP"
        elif "192" in algorithm:
            key = b"8slRzzty6dKMaFCP8slRzzty"
        else:
            key = b"8slRzzty6dKMaFCP8slRzzty6dKMaFCP"

        key_encrypt = backend_encrypt(key, algorithm)
        key_decrypt = backend_decrypt(key, algorithm)
        plain_text = b"test"
        aad = b"extra data" if "GCM" in algorithm else None

        iv, cipher_text, tag = key_encrypt.encrypt(plain_text, aad)

        # verify decrypt to original plain text
        actual = key_decrypt.decrypt(cipher_text, iv, aad, tag)
        assert actual == plain_text

        with pytest.raises(JWEError):
            key_decrypt.decrypt(b"n" * 64)

    @pytest.mark.parametrize("backend_key_wrap", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("backend_key_unwrap", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("algorithm", ALGORITHMS.AES_KW)
    def test_wrap_parity(self, backend_key_wrap, backend_key_unwrap, algorithm):
        if "128" in algorithm:
            key = b"8slRzzty6dKMaFCP"
        elif "192" in algorithm:
            key = b"8slRzzty6dKMaFCP8slRzzty"
        else:
            key = b"8slRzzty6dKMaFCP8slRzzty6dKMaFCP"

        key_wrap = backend_key_wrap(key, algorithm)
        key_unwrap = backend_key_unwrap(key, algorithm)
        plain_text = b"sixteen byte key"

        wrapped_key = key_wrap.wrap_key(plain_text)

        # verify unwrap_key to original plain text
        actual = key_unwrap.unwrap_key(wrapped_key)
        assert actual == plain_text

        with pytest.raises(JWEError):
            key_unwrap.decrypt(b"n" * 64)
