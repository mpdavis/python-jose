import pytest

try:
    from jose.backends.cryptography_backend import CryptographyHMACKey
except ImportError:
    CryptographyHMACKey = None

from jose.backends.native import HMACKey
from jose.constants import ALGORITHMS

CRYPTO_BACKENDS = (
    pytest.param(CryptographyHMACKey, id="pyca/cryptography"),
    pytest.param(HMACKey, id="native"),
)

SUPPORTED_ALGORITHMS = ALGORITHMS.HMAC


@pytest.mark.backend_compatibility
@pytest.mark.skipif(
    CryptographyHMACKey is None, reason="Multiple crypto backends not available for backend compatibility tests"
)
class TestBackendAesCompatibility:
    @pytest.mark.parametrize("backend_sign", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("backend_verify", CRYPTO_BACKENDS)
    @pytest.mark.parametrize("algorithm", SUPPORTED_ALGORITHMS)
    def test_encryption_parity(self, backend_sign, backend_verify, algorithm):
        if "128" in algorithm:
            key = b"8slRzzty6dKMaFCP"
        elif "192" in algorithm:
            key = b"8slRzzty6dKMaFCP8slRzzty"
        else:
            key = b"8slRzzty6dKMaFCP8slRzzty6dKMaFCP"

        key_sign = backend_sign(key, algorithm)
        key_verify = backend_verify(key, algorithm)

        message = b"test"

        digest = key_sign.sign(message)

        assert key_verify.verify(message, digest)

        assert not key_verify.verify(b"not the message", digest)

        assert not key_verify.verify(digest, b"not the digest")
