import base64
import json

import pytest

try:
    from jose.backends.cryptography_backend import CryptographyHMACKey
except ImportError:
    CryptographyHMACKey = None

from jose.backends.native import HMACKey
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError

HMAC_KEY_CLASSES = [pytest.param(HMACKey, id="native")]
if CryptographyHMACKey is not None:
    HMAC_KEY_CLASSES.append(pytest.param(CryptographyHMACKey, id="pyca/cryptography"))

# An EC P-256 key, as a DER SubjectPublicKeyInfo and a DER PKCS#8 private key.
der_public_key = base64.b64decode(
    b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERxw+dYxJBChbun5TEY7Q9SSt6wdX0lvS+Oew1236"
    b"cUzdUg96yoqLkXrMN/Ud6PDJu+OthYOC5wLcJaEtCfeoWA=="
)
der_private_key = base64.b64decode(
    b"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEjRWeJCrze8SNFZ4kKvN7xI0VniQ"
    b"q83vEjRWeJCrze+hRANCAARHHD51jEkEKFu6flMRjtD1JK3rB1fSW9L457DXbfpxTN1SD3rKiouR"
    b"esw39R3o8Mm7462Fg4LnAtwloS0J96hY"
)


class TestHMACAlgorithm:
    def test_non_string_key(self):
        with pytest.raises(JOSEError):
            HMACKey(object(), ALGORITHMS.HS256)

    def test_RSA_key(self):
        key = "-----BEGIN PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "-----BEGIN RSA PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "-----BEGIN CERTIFICATE-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "ssh-rsa"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

    @pytest.mark.parametrize("key_class", HMAC_KEY_CLASSES)
    @pytest.mark.parametrize(
        "key",
        (pytest.param(der_public_key, id="public"), pytest.param(der_private_key, id="private")),
    )
    def test_DER_key(self, key_class, key):
        with pytest.raises(JOSEError):
            key_class(key, ALGORITHMS.HS256)

    def test_to_dict(self):
        passphrase = "The quick brown fox jumps over the lazy dog"
        encoded = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw"
        key = HMACKey(passphrase, ALGORITHMS.HS256)

        as_dict = key.to_dict()
        assert "alg" in as_dict
        assert as_dict["alg"] == ALGORITHMS.HS256

        assert "kty" in as_dict
        assert as_dict["kty"] == "oct"

        assert "k" in as_dict
        assert as_dict["k"] == encoded

        # as_dict should be serializable to JSON
        json.dumps(as_dict)
