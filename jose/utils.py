import base64
import re
import struct

# Piggyback of the backends implementation of the function that converts a long
# to a bytes stream. Some plumbing is necessary to have the signatures match.
try:
    from cryptography.utils import int_to_bytes as _long_to_bytes

    def long_to_bytes(n, blocksize=0):
        return _long_to_bytes(n, blocksize or None)

except ImportError:
    from ecdsa.ecdsa import int_to_string as _long_to_bytes

    def long_to_bytes(n, blocksize=0):
        ret = _long_to_bytes(n)
        if blocksize == 0:
            return ret
        else:
            assert len(ret) <= blocksize
            padding = blocksize - len(ret)
            return b"\x00" * padding + ret


def long_to_base64(data, size=0):
    return base64.urlsafe_b64encode(long_to_bytes(data, size)).strip(b"=")


def int_arr_to_long(arr):
    return int("".join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, str):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b"==")
    return int_arr_to_long(struct.unpack("%sB" % len(_d), _d))


def calculate_at_hash(access_token, hash_alg):
    """Helper method for calculating an access token
    hash, as described in http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

    Its value is the base64url encoding of the left-most half of the hash of the octets
    of the ASCII representation of the access_token value, where the hash algorithm
    used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE
    Header. For instance, if the alg is RS256, hash the access_token value with SHA-256,
    then take the left-most 128 bits and base64url encode them. The at_hash value is a
    case sensitive string.

    Args:
        access_token (str): An access token string.
        hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256

    """
    hash_digest = hash_alg(access_token.encode("utf-8")).digest()
    cut_at = int(len(hash_digest) / 2)
    truncated = hash_digest[:cut_at]
    at_hash = base64url_encode(truncated)
    return at_hash.decode("utf-8")


def base64url_decode(input):
    """Helper method to base64url_decode a string.

    Args:
        input (bytes): A base64url_encoded string (bytes) to decode.

    """
    rem = len(input) % 4

    if rem > 0:
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    """Helper method to base64url_encode a string.

    Args:
        input (bytes): A base64url_encoded string (bytes) to encode.

    """
    return base64.urlsafe_b64encode(input).replace(b"=", b"")


def timedelta_total_seconds(delta):
    """Helper method to determine the total number of seconds
    from a timedelta.

    Args:
        delta (timedelta): A timedelta to convert to seconds.
    """
    return delta.days * 24 * 60 * 60 + delta.seconds


def ensure_binary(s):
    """Coerce **s** to bytes."""

    if isinstance(s, bytes):
        return s
    if isinstance(s, str):
        return s.encode("utf-8", "strict")
    raise TypeError(f"not expecting type '{type(s)}'")


# The following was copied from PyJWT:
#   https://github.com/jpadilla/pyjwt/commit/9c528670c455b8d948aff95ed50e22940d1ad3fc
# Based on:
#   https://github.com/hynek/pem/blob/7ad94db26b0bc21d10953f5dbad3acfdfacf57aa/src/pem/_core.py#L224-L252
_PEMS = {
    b"CERTIFICATE",
    b"TRUSTED CERTIFICATE",
    b"PRIVATE KEY",
    b"PUBLIC KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"RSA PRIVATE KEY",
    b"RSA PUBLIC KEY",
    b"EC PRIVATE KEY",
    b"DH PARAMETERS",
    b"NEW CERTIFICATE REQUEST",
    b"CERTIFICATE REQUEST",
    b"SSH2 PUBLIC KEY",
    b"SSH2 ENCRYPTED PRIVATE KEY",
    b"X509 CRL",
}
_PEM_RE = re.compile(
    b"----[- ]BEGIN (" + b"|".join(re.escape(pem) for pem in _PEMS) + b")[- ]----",
)


def is_pem_format(key: bytes) -> bool:
    return bool(_PEM_RE.search(key))


# Based on
# https://github.com/pyca/cryptography/blob/bcb70852d577b3f490f015378c75cba74986297b
#   /src/cryptography/hazmat/primitives/serialization/ssh.py#L40-L46
_CERT_SUFFIX = b"-cert-v01@openssh.com"
_SSH_PUBKEY_RC = re.compile(rb"\A(\S+)[ \t]+(\S+)")
_SSH_KEY_FORMATS = [
    b"ssh-ed25519",
    b"ssh-rsa",
    b"ssh-dss",
    b"ecdsa-sha2-nistp256",
    b"ecdsa-sha2-nistp384",
    b"ecdsa-sha2-nistp521",
]


def is_ssh_key(key: bytes) -> bool:
    if any(string_value in key for string_value in _SSH_KEY_FORMATS):
        return True
    ssh_pubkey_match = _SSH_PUBKEY_RC.match(key)
    if ssh_pubkey_match:
        key_type = ssh_pubkey_match.group(1)
        if _CERT_SUFFIX == key_type[-len(_CERT_SUFFIX) :]:
            return True
    return False


_DER_INTEGER = 0x02
_DER_SEQUENCE = 0x30
_DER_CONSTRUCTED = 0x20


def _read_der_element(key: bytes, pos: int):
    """Parse the DER element at ``pos``.

    Returns its ``(tag, content_start, end)`` offsets, or ``None`` if the
    element is not well-formed DER.
    """
    if pos + 2 > len(key):
        return None
    tag = key[pos]
    length = key[pos + 1]
    content_start = pos + 2
    if length & 0x80:
        # Long form: the low bits hold the number of subsequent length bytes.
        # Zero of them means the indefinite length that DER forbids.
        length_bytes = length & 0x7F
        if not 1 <= length_bytes <= 4 or content_start + length_bytes > len(key):
            return None
        length = int.from_bytes(key[content_start : content_start + length_bytes], "big")
        content_start += length_bytes
    end = content_start + length
    if end > len(key):
        return None
    return tag, content_start, end


def _are_der_elements_well_formed(key: bytes, pos: int, end: int) -> bool:
    """Whether ``key[pos:end]`` is a sequence of DER elements that tile it exactly."""
    while pos < end:
        element = _read_der_element(key, pos)
        if element is None:
            return False
        tag, content_start, element_end = element
        if element_end > end:
            return False
        # Only constructed elements hold further elements; the contents of a
        # primitive one (a BIT STRING wrapping a key, say) are opaque bytes.
        if tag & _DER_CONSTRUCTED and not _are_der_elements_well_formed(key, content_start, element_end):
            return False
        pos = element_end
    return True


def is_der_format(key: bytes) -> bool:
    """Whether ``key`` is a DER-encoded asymmetric key or x509 certificate.

    DER has no armor or prefix to match on, so it is recognized by its ASN.1
    structure instead: a single SEQUENCE spanning the whole input, opening with
    the SEQUENCE (an AlgorithmIdentifier or TBSCertificate) or INTEGER (a
    version or modulus) that every such encoding starts with.
    """
    element = _read_der_element(key, 0)
    if element is None:
        return False
    tag, content_start, end = element
    if tag != _DER_SEQUENCE or end != len(key):
        return False
    first_child = _read_der_element(key, content_start)
    if first_child is None or first_child[0] not in (_DER_SEQUENCE, _DER_INTEGER):
        return False
    return _are_der_elements_well_formed(key, content_start, end)
