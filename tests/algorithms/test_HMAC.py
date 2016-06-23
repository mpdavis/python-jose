
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError
from jose.jwk import HMACKey

import pytest


class TestHMACAlgorithm:

    def test_non_string_key(self):
        with pytest.raises(JOSEError):
            HMACKey(object(), ALGORITHMS.HS256)

    def test_RSA_key(self):
        key = "-----BEGIN PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "-----BEGIN CERTIFICATE-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "ssh-rsa"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)
