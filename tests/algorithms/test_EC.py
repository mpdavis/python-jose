
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

    def test_EC_key(self):
        key = ecdsa.SigningKey.from_pem(private_key)
        ECDSAECKey(key, ALGORITHMS.ES256)
        CryptographyECKey(key, ALGORITHMS.ES256)

        ECDSAECKey(private_key, ALGORITHMS.ES256)
        CryptographyECKey(private_key, ALGORITHMS.ES256)

    def test_string_secret(self):
        key = 'secret'
        with pytest.raises(JOSEError):
            ECDSAECKey(key, ALGORITHMS.ES256)

        with pytest.raises(JOSEError):
            CryptographyECKey(key, ALGORITHMS.ES256)

    def test_object(self):
        key = object()
        with pytest.raises(JOSEError):
            ECDSAECKey(key, ALGORITHMS.ES256)

        with pytest.raises(JOSEError):
            CryptographyECKey(key, ALGORITHMS.ES256)

    def test_invalid_algorithm(self):
        with pytest.raises(JWKError):
            ECDSAECKey({'kty': 'bla'}, ALGORITHMS.ES256)

    def test_EC_jwk(self):
        key = {
            "kty": "EC",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "crv": "P-521",
            "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
            "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
            "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
        }

        ECDSAECKey(key, ALGORITHMS.ES512)
        CryptographyECKey(key, ALGORITHMS.ES512)

        del key['d']

        # We are now dealing with a public key.
        ECDSAECKey(key, ALGORITHMS.ES512)
        CryptographyECKey(key, ALGORITHMS.ES512)

        del key['x']

        # This key is missing a required parameter.
        with pytest.raises(JWKError):
            ECDSAECKey(key, ALGORITHMS.ES512)

        with pytest.raises(JWKError):
            CryptographyECKey(key, ALGORITHMS.ES512)

    def test_verify(self):
        key = ECDSAECKey(private_key, ALGORITHMS.ES256)
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

    def test_to_dict(self):
        key = CryptographyECKey(private_key, ALGORITHMS.ES256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)

        key = ECDSAECKey(private_key, ALGORITHMS.ES256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)
