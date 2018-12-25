import sys

try:
    from Crypto.PublicKey import RSA as PyCryptoRSA
    from jose.backends.pycrypto_backend import RSAKey as PyCryptoRSAKey
except ImportError:
    PyCryptoRSA = PyCryptoRSAKey = None

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa as pyca_rsa
    from jose.backends.cryptography_backend import CryptographyRSAKey
except ImportError:
    default_backend = pyca_rsa = CryptographyRSAKey = None

from jose.backends import RSAKey
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError, JWKError

import pytest

# Deal with integer compatibilities between Python 2 and 3.
# Using `from builtins import int` is not supported on AppEngine.
if sys.version_info > (3,):
    long = int

private_key = b"""-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""


@pytest.mark.pycrypto
@pytest.mark.pycryptodome
@pytest.mark.skipif(None in (PyCryptoRSA, PyCryptoRSAKey), reason="Pycrypto/dome backend not available")
def test_pycrypto_RSA_key_instance():
    key = PyCryptoRSA.construct((long(
        26057131595212989515105618545799160306093557851986992545257129318694524535510983041068168825614868056510242030438003863929818932202262132630250203397069801217463517914103389095129323580576852108653940669240896817348477800490303630912852266209307160550655497615975529276169196271699168537716821419779900117025818140018436554173242441334827711966499484119233207097432165756707507563413323850255548329534279691658369466534587631102538061857114141268972476680597988266772849780811214198186940677291891818952682545840788356616771009013059992237747149380197028452160324144544057074406611859615973035412993832273216732343819),
                         long(65537)))
    PyCryptoRSAKey(key, ALGORITHMS.RS256)

# TODO: Unclear why this test was marked as only for pycrypto
@pytest.mark.pycrypto
@pytest.mark.pycryptodome
def test_pycrypto_unencoded_cleartext():
    key = RSAKey(private_key, ALGORITHMS.RS256)
    msg = b'test'
    signature = key.sign(msg)
    public_key = key.public_key()

    assert bool(public_key.verify(msg, signature))
    assert not bool(public_key.verify(msg, 1))


@pytest.mark.cryptography
@pytest.mark.skipif(
    None in (default_backend, pyca_rsa, CryptographyRSAKey),
    reason="Cryptography backend not available"
)
def test_cryptography_RSA_key_instance():

    key = pyca_rsa.RSAPublicNumbers(
        long(65537),
        long(26057131595212989515105618545799160306093557851986992545257129318694524535510983041068168825614868056510242030438003863929818932202262132630250203397069801217463517914103389095129323580576852108653940669240896817348477800490303630912852266209307160550655497615975529276169196271699168537716821419779900117025818140018436554173242441334827711966499484119233207097432165756707507563413323850255548329534279691658369466534587631102538061857114141268972476680597988266772849780811214198186940677291891818952682545840788356616771009013059992237747149380197028452160324144544057074406611859615973035412993832273216732343819),
    ).public_key(default_backend())

    pubkey = CryptographyRSAKey(key, ALGORITHMS.RS256)
    assert pubkey.is_public()

    pem = pubkey.to_pem()
    assert pem.startswith(b'-----BEGIN PUBLIC KEY-----')


class TestRSAAlgorithm:
    def test_RSA_key(self):
        assert not RSAKey(private_key, ALGORITHMS.RS256).is_public()

    def test_string_secret(self):
        key = 'secret'
        with pytest.raises(JOSEError):
            RSAKey(key, ALGORITHMS.RS256)

    def test_object(self):
        key = object()
        with pytest.raises(JOSEError):
            RSAKey(key, ALGORITHMS.RS256)

    def test_bad_cert(self,):
        key = '-----BEGIN CERTIFICATE-----'
        with pytest.raises(JOSEError):
            RSAKey(key, ALGORITHMS.RS256)

    def test_invalid_algorithm(self):
        with pytest.raises(JWKError):
            RSAKey(private_key, ALGORITHMS.ES256)

        with pytest.raises(JWKError):
            RSAKey({'kty': 'bla'}, ALGORITHMS.RS256)

    def test_RSA_jwk(self):
        key = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        }
        assert RSAKey(key, ALGORITHMS.RS256).is_public()

        key = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
            "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
            "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
            "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
            "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX 59ehik",
            "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
            "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"
        }
        assert not RSAKey(key, ALGORITHMS.RS256).is_public()

        del key['p']

        # Some but not all extra parameters are present
        with pytest.raises(JWKError):
            RSAKey(key, ALGORITHMS.RS256)

        del key['q']
        del key['dp']
        del key['dq']
        del key['qi']

        # None of the extra parameters are present, but 'key' is still private.
        assert not RSAKey(key, ALGORITHMS.RS256).is_public()

    def test_get_public_key(self):
        key = RSAKey(private_key, ALGORITHMS.RS256)
        public_key = key.public_key()
        public_key2 = public_key.public_key()
        assert public_key.is_public()
        assert public_key2.is_public()
        assert public_key == public_key2

    def test_to_pem(self):
        key = RSAKey(private_key, ALGORITHMS.RS256)
        assert key.to_pem(pem_format='PKCS1').strip() == private_key.strip()

        pkcs8 = key.to_pem(pem_format='PKCS8').strip()
        assert pkcs8 != private_key.strip()

        newkey = RSAKey(pkcs8, ALGORITHMS.RS256)
        assert newkey.to_pem(pem_format='PKCS1').strip() == private_key.strip()

    def assert_parameters(self, as_dict, private):
        assert isinstance(as_dict, dict)

        # Public parameters should always be there.
        assert 'n' in as_dict
        assert 'e' in as_dict

        if private:
            # Private parameters as well
            assert 'd' in as_dict
            assert 'p' in as_dict
            assert 'q' in as_dict
            assert 'dp' in as_dict
            assert 'dq' in as_dict
            assert 'qi' in as_dict
        else:
            # Private parameters should be absent
            assert 'd' not in as_dict
            assert 'p' not in as_dict
            assert 'q' not in as_dict
            assert 'dp' not in as_dict
            assert 'dq' not in as_dict
            assert 'qi' not in as_dict

    def assert_roundtrip(self, key):
        assert RSAKey(
            key.to_dict(),
            ALGORITHMS.RS256
        ).to_dict() == key.to_dict()

    def test_to_dict(self):
        key = RSAKey(private_key, ALGORITHMS.RS256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)
        self.assert_roundtrip(key)
        self.assert_roundtrip(key.public_key())
