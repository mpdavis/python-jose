from binascii import hexlify, unhexlify

import pytest

from jose.constants import ALGORITHMS

try:
    from jose.backends.pycrypto_backend import AESKey as PyCryptoAESKey
except ImportError as e:
    PyCryptoAESKey = None

try:
    from jose.backends.cryptography_backend import CryptographyAESKey
except ImportError as e:
    CryptographyAESKey = None


# List of Tuple of (alg, key, kek, wrapped) obtained from
# https://tools.ietf.org/html/rfc3394#section-2.2.3.1
VECTORS = (
    (
        ALGORITHMS.A128KW,
        b"00112233445566778899AABBCCDDEEFF",
        b"000102030405060708090A0B0C0D0E0F",
        b"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
    ),
    (
        ALGORITHMS.A192KW,
        b"00112233445566778899AABBCCDDEEFF0001020304050607",
        b"000102030405060708090A0B0C0D0E0F1011121314151617",
        b"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
    ),
    (
        ALGORITHMS.A256KW,
        b"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        b"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        b"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
    ),
)


@pytest.mark.cryptography
@pytest.mark.skipif(CryptographyAESKey is None, reason="Cryptography backend not available")
class TestCryptographyAesKeywrap:
    @pytest.mark.parametrize("alg,hex_key,hex_kek,expected", VECTORS)
    def test_wrap(self, alg, hex_key, hex_kek, expected):
        bin_key = unhexlify(hex_key)
        bin_kek = unhexlify(hex_kek)
        aes_key = CryptographyAESKey(bin_kek, alg)
        actual = hexlify(aes_key.wrap_key(bin_key)).upper()
        assert actual == expected

    @pytest.mark.parametrize("alg,expected,hex_kek,hex_wrapped", VECTORS)
    def test_unwrap(self, alg, expected, hex_kek, hex_wrapped):
        bin_kek = unhexlify(hex_kek)
        bin_wrapped = unhexlify(hex_wrapped)
        aes_key = CryptographyAESKey(bin_kek, alg)
        actual = hexlify(aes_key.unwrap_key(bin_wrapped)).upper()
        assert actual == expected
