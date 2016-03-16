
from jose.jwk import HMACKey
from jose.exceptions import JOSEError

import pytest


class TestHMACAlgorithm:

    def test_non_string_key(self):
        with pytest.raises(JOSEError):
            HMACKey(object(), HMACKey.SHA256)

    def test_RSA_key(self):
        key = "-----BEGIN PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            HMACKey(key, HMACKey.SHA256)

        key = "-----BEGIN CERTIFICATE-----"
        with pytest.raises(JOSEError):
            HMACKey(key, HMACKey.SHA256)

        key = "ssh-rsa"
        with pytest.raises(JOSEError):
            HMACKey(key, HMACKey.SHA256)
