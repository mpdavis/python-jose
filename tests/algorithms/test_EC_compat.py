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
class TestBackendEcdsaCompatibility(object):

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

    @pytest.mark.parametrize("BackendFrom", [ECDSAECKey, CryptographyECKey])
    @pytest.mark.parametrize("BackendTo", [ECDSAECKey, CryptographyECKey])
    def test_public_key_to_pem(self, BackendFrom, BackendTo):
        key = BackendFrom(private_key, ALGORITHMS.ES256)
        key2 = BackendTo(private_key, ALGORITHMS.ES256)

        assert key.public_key().to_pem().strip() == key2.public_key().to_pem().strip()

    @pytest.mark.parametrize("BackendFrom", [ECDSAECKey, CryptographyECKey])
    @pytest.mark.parametrize("BackendTo", [ECDSAECKey, CryptographyECKey])
    def test_private_key_to_pem(self, BackendFrom, BackendTo):
        key = BackendFrom(private_key, ALGORITHMS.ES256)
        key2 = BackendTo(private_key, ALGORITHMS.ES256)

        assert key.to_pem().strip() == key2.to_pem().strip()

    @pytest.mark.parametrize("BackendFrom", [ECDSAECKey, CryptographyECKey])
    @pytest.mark.parametrize("BackendTo", [ECDSAECKey, CryptographyECKey])
    def test_public_key_load_cycle(self, BackendFrom, BackendTo):
        key = BackendFrom(private_key, ALGORITHMS.ES256)
        pubkey = key.public_key()

        pub_pem_source = pubkey.to_pem().strip()

        pub_target = BackendTo(pub_pem_source, ALGORITHMS.ES256)

        assert pub_pem_source == pub_target.to_pem().strip()

    @pytest.mark.parametrize("BackendFrom", [ECDSAECKey, CryptographyECKey])
    @pytest.mark.parametrize("BackendTo", [ECDSAECKey, CryptographyECKey])
    def test_private_key_load_cycle(self, BackendFrom, BackendTo):
        key = BackendFrom(private_key, ALGORITHMS.ES256)

        pem_source = key.to_pem().strip()

        target = BackendTo(pem_source, ALGORITHMS.ES256)

        assert pem_source == target.to_pem().strip()
