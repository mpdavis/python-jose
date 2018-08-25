import pytest

try:
    from jose.backends.ecdsa_backend import ECDSAECKey
    from jose.backends.cryptography_backend import CryptographyECKey
except ImportError:
    ECDSAECKey = CryptographyECKey = None
from jose.constants import ALGORITHMS

from .test_EC import private_key


@pytest.mark.backend_compatibility
@pytest.mark.skipif(
    None in (ECDSAECKey, CryptographyECKey),
    reason="Multiple crypto backends not available for backend compatibility tests"
)
class TestBackendRsaCompatibility(object):

    @pytest.mark.parametrize("BackendSign", [ECDSAECKey, CryptographyECKey])
    @pytest.mark.parametrize("BackendVerify", [ECDSAECKey, CryptographyECKey])
    def test_signing_parity(self, BackendSign, BackendVerify):
        key_sign = BackendSign(private_key, ALGORITHMS.ES256)
        key_verify = BackendVerify(private_key, ALGORITHMS.ES256).public_key()

        msg = b'test'
        sig = key_sign.sign(msg)

        # valid signature
        assert key_verify.verify(msg, sig)

        # invalid signature
        assert not key_verify.verify(msg, b'n' * 64)
