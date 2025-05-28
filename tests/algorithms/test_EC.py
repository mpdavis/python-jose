import base64
import json
import re

from jose import jwt
from jose.backends import ECKey
from jose.constants import ALGORITHMS
from jose.exceptions import JOSEError, JWKError

try:
    import ecdsa

    from jose.backends.ecdsa_backend import ECDSAECKey
except ImportError:
    ECDSAECKey = ecdsa = None

try:
    from cryptography.hazmat.backends import default_backend as CryptographyBackend
    from cryptography.hazmat.primitives import hashes, hmac, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as CryptographyEc

    from jose.backends.cryptography_backend import CryptographyECKey

except ImportError:
    CryptographyECKey = CryptographyEc = CryptographyBackend = None

import pytest

private_key = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOiSs10XnBlfykk5zsJRmzYybKdMlGniSJcssDvUcF6DoAoGCCqGSM49
AwEHoUQDQgAE7gb4edKJ7ul9IgomCdcOebQTZ8qktqtBfRKboa71CfEKzBruUi+D
WkG0HJWIORlPbvXME+DRh6G/yVOKnTm88Q==
-----END EC PRIVATE KEY-----"""

# Private key generated using NIST256p curve
TOO_SHORT_PRIVATE_KEY = b"""\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMlUyYGOpjV4bbW0C9FKS2zkspD0L/5vJLnr6sJoLdc+oAoGCCqGSM49
AwEHoUQDQgAE6TDUNj5QXl+RKdZvBV+cg7Td6cJRB+Ta8XAhIuCAzonq0Ix//1+C
pNSsy11sIKmMl61YJzxvZ6WkNluBmkDPCQ==
-----END EC PRIVATE KEY-----
"""

# ES256 signatures generated to test conversion logic
DER_SIGNATURE = (
    b"0F\x02!\x00\x89yG\x81W\x01\x11\x9b0\x08\xa4\xd0\xe3g([\x07\xb5\x01\xb3"
    b"\x9d\xdf \xd1\xbc\xedK\x01\x87:}\xf2\x02!\x00\xb2shTA\x00\x1a\x13~\xba"
    b"J\xdb\xeem\x12\x1e\xfeMO\x04\xb2[\x86A\xbd\xc6hu\x953X\x1e"
)
RAW_SIGNATURE = (
    b"\x89yG\x81W\x01\x11\x9b0\x08\xa4\xd0\xe3g([\x07\xb5\x01\xb3\x9d\xdf "
    b"\xd1\xbc\xedK\x01\x87:}\xf2\xb2shTA\x00\x1a\x13~\xbaJ\xdb\xeem\x12\x1e"
    b"\xfeMO\x04\xb2[\x86A\xbd\xc6hu\x953X\x1e"
)

# Define the regex pattern to capture the header, body, and footer of the PEM file
PEM_REGEX = re.compile(r"(-----BEGIN [A-Z ]+-----)(.*?)(-----END [A-Z ]+-----)", re.DOTALL)
WHITE_SPACE_REGEX = re.compile(r"\s+")


def get_pem_for_key(key):
    return key.to_pem().strip().decode("utf-8")


def normalize_pem(key_pem_str):
    # Search for the PEM sections
    pem_match = PEM_REGEX.search(key_pem_str)
    if not pem_match:
        raise ValueError("The provided string does not contain a valid PEM formatted data.")

    header = pem_match.group(1)
    body = pem_match.group(2)
    footer = pem_match.group(3)

    # Remove all newlines and spaces from the body
    clean_body = WHITE_SPACE_REGEX.sub("", body)

    # Reassemble the PEM string
    return f"{header}\n{clean_body}\n{footer}"


def _backend_exception_types():
    """Build the backend exception types based on available backends."""
    if None not in (ECDSAECKey, ecdsa):
        yield ECDSAECKey, ecdsa.BadDigestError

    if CryptographyECKey is not None:
        yield CryptographyECKey, TypeError


@pytest.mark.ecdsa
@pytest.mark.skipif(None in (ECDSAECKey, ecdsa), reason="python-ecdsa backend not available")
def test_key_from_ecdsa():
    key = ecdsa.SigningKey.from_pem(private_key)
    assert not ECKey(key, ALGORITHMS.ES256).is_public()


@pytest.mark.cryptography
@pytest.mark.skipif(CryptographyECKey is None, reason="pyca/cryptography backend not available")
@pytest.mark.parametrize(
    "algorithm, expected_length", ((ALGORITHMS.ES256, 32), (ALGORITHMS.ES384, 48), (ALGORITHMS.ES512, 66))
)
def test_cryptography_sig_component_length(algorithm, expected_length):
    # Put mapping inside here to avoid more complex handling for test runs that do not have pyca/cryptography
    mapping = {
        ALGORITHMS.ES256: CryptographyEc.SECP256R1,
        ALGORITHMS.ES384: CryptographyEc.SECP384R1,
        ALGORITHMS.ES512: CryptographyEc.SECP521R1,
    }
    key = CryptographyECKey(
        CryptographyEc.generate_private_key(mapping[algorithm](), backend=CryptographyBackend()), algorithm
    )
    assert key._sig_component_length() == expected_length


@pytest.mark.cryptography
@pytest.mark.skipif(CryptographyECKey is None, reason="pyca/cryptography backend not available")
def test_cryptograhy_der_to_raw():
    key = CryptographyECKey(private_key, ALGORITHMS.ES256)
    assert key._der_to_raw(DER_SIGNATURE) == RAW_SIGNATURE


@pytest.mark.cryptography
@pytest.mark.skipif(CryptographyECKey is None, reason="pyca/cryptography backend not available")
def test_cryptograhy_raw_to_der():
    key = CryptographyECKey(private_key, ALGORITHMS.ES256)
    assert key._raw_to_der(RAW_SIGNATURE) == DER_SIGNATURE


class TestECAlgorithm:
    def test_key_from_pem(self):
        assert not ECKey(private_key, ALGORITHMS.ES256).is_public()

    def test_to_pem(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        assert not key.is_public()
        assert normalize_pem(get_pem_for_key(key)) == normalize_pem(private_key.strip())

        public_pem = key.public_key().to_pem()
        assert ECKey(public_pem, ALGORITHMS.ES256).is_public()

    @pytest.mark.parametrize("Backend,ExceptionType", _backend_exception_types())
    def test_key_too_short(self, Backend, ExceptionType):
        key = Backend(TOO_SHORT_PRIVATE_KEY, ALGORITHMS.ES512)
        with pytest.raises(ExceptionType):
            key.sign(b"foo")

    def test_get_public_key(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        pubkey = key.public_key()
        pubkey2 = pubkey.public_key()
        assert pubkey == pubkey2

    def test_string_secret(self):
        key = "secret"
        with pytest.raises(JOSEError):
            ECKey(key, ALGORITHMS.ES256)

    def test_object(self):
        key = object()
        with pytest.raises(JOSEError):
            ECKey(key, ALGORITHMS.ES256)

    def test_invalid_algorithm(self):
        with pytest.raises(JWKError):
            ECKey(private_key, "nonexistent")

        with pytest.raises(JWKError):
            ECKey({"kty": "bla"}, ALGORITHMS.ES256)

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

        assert not ECKey(key, ALGORITHMS.ES512).is_public()

        del key["d"]

        # We are now dealing with a public key.
        assert ECKey(key, ALGORITHMS.ES512).is_public()

        del key["x"]

        # This key is missing a required parameter.
        with pytest.raises(JWKError):
            ECKey(key, ALGORITHMS.ES512)

    def test_verify(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        msg = b"test"
        signature = key.sign(msg)
        public_key = key.public_key()

        assert bool(public_key.verify(msg, signature))
        assert not bool(public_key.verify(msg, b"not a signature"))

    def assert_parameters(self, as_dict, private):
        assert isinstance(as_dict, dict)

        # Public parameters should always be there.
        assert "x" in as_dict
        assert "y" in as_dict
        assert "crv" in as_dict

        assert "kty" in as_dict
        assert as_dict["kty"] == "EC"

        if private:
            # Private parameters as well
            assert "d" in as_dict

        else:
            # Private parameters should be absent
            assert "d" not in as_dict

        # as_dict should be serializable to JSON
        json.dumps(as_dict)

    def test_to_dict(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)


@pytest.mark.cryptography
@pytest.mark.skipif(CryptographyECKey is None, reason="pyca/cryptography backend not available")
def test_incorrect_public_key_hmac_signing():
    def b64(x):
        return base64.urlsafe_b64encode(x).replace(b"=", b"")

    KEY = CryptographyEc.generate_private_key(CryptographyEc.SECP256R1)
    PUBKEY = KEY.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    # Create and sign the payload using a public key, but specify the "alg" in
    # the claims that a symmetric key was used.
    payload = b64(b'{"alg":"HS256"}') + b"." + b64(b'{"pwned":true}')
    hasher = hmac.HMAC(PUBKEY, hashes.SHA256())
    hasher.update(payload)
    evil_token = payload + b"." + b64(hasher.finalize())

    # Verify and decode the token using the public key. The custom algorithm
    # field is left unspecified. Decoding using a public key should be
    # rejected raising a JWKError.
    with pytest.raises(JWKError):
        jwt.decode(evil_token, PUBKEY)
