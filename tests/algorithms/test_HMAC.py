import json

import pytest

from jose.backends.native import HMACKey
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError


class TestKeyVerification:
    def test_invalid_key_for_hmac(self):
        rsa_keys = [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "ssh-rsa"
        ]
        for key in rsa_keys:
            with pytest.raises(JOSEError):
                HMACKey(key, ALGORITHMS.HS256)

    def test_key_verification_logic(self):
        # Add tests to validate the new key verification logic
        pass

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
