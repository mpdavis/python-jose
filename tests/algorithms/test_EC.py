
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError, JWKError

from jose.backends.ecdsa_backend import ECDSAECKey
from jose.backends.cryptography_backend import CryptographyECKey

import ecdsa
import pytest

private_key = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOiSs10XnBlfykk5zsJRmzYybKdMlGniSJcssDvUcF6DoAoGCCqGSM49
AwEHoUQDQgAE7gb4edKJ7ul9IgomCdcOebQTZ8qktqtBfRKboa71CfEKzBruUi+D
WkG0HJWIORlPbvXME+DRh6G/yVOKnTm88Q==
-----END EC PRIVATE KEY-----"""


class TestECAlgorithm:

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_key_from_pem(self, Backend):
        assert not Backend(private_key, ALGORITHMS.ES256).is_public()

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_key_from_ecdsa(self, Backend):
        key = ecdsa.SigningKey.from_pem(private_key)
        assert not Backend(key, ALGORITHMS.ES256).is_public()

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_to_pem(self, Backend):
        key = Backend(private_key, ALGORITHMS.ES256)
        assert not key.is_public()
        assert key.to_pem().strip() == private_key.strip().encode('utf-8')

        public_pem = key.public_key().to_pem()
        assert Backend(public_pem, ALGORITHMS.ES256).is_public()

    @pytest.mark.parametrize(
        "Backend,ExceptionType",
        [
            (ECDSAECKey, ecdsa.BadDigestError),
            (CryptographyECKey, TypeError)
        ]
    )
    def test_key_too_short(self, Backend, ExceptionType):
        priv_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p).to_pem()
        key = Backend(priv_key, ALGORITHMS.ES512)
        with pytest.raises(ExceptionType):
            key.sign(b'foo')

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_get_public_key(self, Backend):
        key = Backend(private_key, ALGORITHMS.ES256)
        pubkey = key.public_key()
        pubkey2 = pubkey.public_key()
        assert pubkey == pubkey2

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_string_secret(self, Backend):
        key = 'secret'
        with pytest.raises(JOSEError):
            Backend(key, ALGORITHMS.ES256)

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_object(self, Backend):
        key = object()
        with pytest.raises(JOSEError):
            Backend(key, ALGORITHMS.ES256)

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_invalid_algorithm(self, Backend):
        with pytest.raises(JWKError):
            Backend(private_key, 'nonexistent')

        with pytest.raises(JWKError):
            Backend({'kty': 'bla'}, ALGORITHMS.ES256)

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_EC_jwk(self, Backend):
        key = {
            "kty": "EC",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "crv": "P-521",
            "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
            "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
            "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
        }

        assert not Backend(key, ALGORITHMS.ES512).is_public()

        del key['d']

        # We are now dealing with a public key.
        assert Backend(key, ALGORITHMS.ES512).is_public()

        del key['x']

        # This key is missing a required parameter.
        with pytest.raises(JWKError):
            Backend(key, ALGORITHMS.ES512)

    @pytest.mark.parametrize("Backend", [ECDSAECKey])
    def test_verify(self, Backend):
        key = Backend(private_key, ALGORITHMS.ES256)
        msg = b'test'
        signature = key.sign(msg)
        public_key = key.public_key()

        assert public_key.verify(msg, signature) == True
        assert public_key.verify(msg, b'not a signature') == False

    def assert_parameters(self, as_dict, private):
        assert isinstance(as_dict, dict)

        # Public parameters should always be there.
        assert 'x' in as_dict
        assert 'y' in as_dict
        assert 'crv' in as_dict

        assert 'kty' in as_dict
        assert as_dict['kty'] == 'EC'

        if private:
            # Private parameters as well
            assert 'd' in as_dict

        else:
            # Private parameters should be absent
            assert 'd' not in as_dict

    @pytest.mark.parametrize("Backend", [ECDSAECKey, CryptographyECKey])
    def test_to_dict(self, Backend):
        key = Backend(private_key, ALGORITHMS.ES256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)

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
