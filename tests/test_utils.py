import base64
from datetime import timedelta

import pytest

from jose import utils

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


class TestUtils:
    def test_total_seconds(self):
        td = timedelta(seconds=5)

        assert utils.timedelta_total_seconds(td) == 5

    def test_long_to_base64(self):
        assert utils.long_to_base64(0xDEADBEEF) == b"3q2-7w"
        assert utils.long_to_base64(0xCAFED00D, size=10) == b"AAAAAAAAyv7QDQ"

    @pytest.mark.parametrize(
        "key",
        (pytest.param(der_public_key, id="public"), pytest.param(der_private_key, id="private")),
    )
    def test_is_der_format(self, key):
        assert utils.is_der_format(key)

    @pytest.mark.parametrize(
        "key",
        (
            b"",
            b"0",
            b"00",
            b"secret",
            b"0123456789",
            b"The quick brown fox jumps over the lazy dog",
            # A SEQUENCE tag (0x30 is also ASCII "0") does not make a secret DER.
            b"0" + b"x" * 121,
            b"0" * 64,
            # Truncated and over-long DER are both malformed.
            der_public_key[:-1],
            der_public_key + b"\x00",
        ),
    )
    def test_is_not_der_format(self, key):
        assert not utils.is_der_format(key)
