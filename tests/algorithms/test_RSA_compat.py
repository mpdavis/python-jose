import pytest

try:
    from jose.backends.rsa_backend import RSAKey as PurePythonRSAKey
    from jose.backends.cryptography_backend import CryptographyRSAKey
    from jose.backends.pycrypto_backend import RSAKey
except ImportError:
    PurePythonRSAKey = CryptographyRSAKey = RSAKey = None
from jose.constants import ALGORITHMS

from .test_RSA import private_key


@pytest.mark.backend_compatibility
@pytest.mark.skipif(
    None in (PurePythonRSAKey, CryptographyRSAKey, RSAKey),
    reason="Multiple crypto backends not available for backend compatibility tests"
)
class TestBackendRsaCompatibility(object):

    @pytest.mark.parametrize("BackendSign", [RSAKey, CryptographyRSAKey, PurePythonRSAKey])
    @pytest.mark.parametrize("BackendVerify", [RSAKey, CryptographyRSAKey, PurePythonRSAKey])
    def test_signing_parity(self, BackendSign, BackendVerify):
        key_sign = BackendSign(private_key, ALGORITHMS.RS256)
        key_verify = BackendVerify(private_key, ALGORITHMS.RS256).public_key()

        msg = b'test'
        sig = key_sign.sign(msg)

        # valid signature
        assert key_verify.verify(msg, sig)

        # invalid signature
        assert not key_verify.verify(msg, b'n' * 64)

    @pytest.mark.parametrize("BackendFrom", [RSAKey, CryptographyRSAKey, PurePythonRSAKey])
    @pytest.mark.parametrize("BackendTo", [RSAKey, CryptographyRSAKey, PurePythonRSAKey])
    def test_public_key_to_pem(self, BackendFrom, BackendTo):
        key = BackendFrom(private_key, ALGORITHMS.RS256)
        pubkey = key.public_key()

        pkcs1_pub = pubkey.to_pem(pem_format='PKCS1').strip()
        pkcs8_pub = pubkey.to_pem(pem_format='PKCS8').strip()
        assert pkcs1_pub != pkcs8_pub, BackendFrom

        pub1 = BackendTo(pkcs1_pub, ALGORITHMS.RS256)
        pub8 = BackendTo(pkcs8_pub, ALGORITHMS.RS256)

        assert pkcs8_pub == pub1.to_pem(pem_format='PKCS8').strip()
        assert pkcs1_pub == pub8.to_pem(pem_format='PKCS1').strip()
