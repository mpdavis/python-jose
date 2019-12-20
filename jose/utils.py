
import base64
import six
import struct
import sys

if sys.version_info > (3,):
    # Deal with integer compatibilities between Python 2 and 3.
    # Using `from builtins import int` is not supported on AppEngine.
    long = int


# Piggyback of the backends implementation of the function that converts a long
# to a bytes stream. Some plumbing is necessary to have the signatures match.
try:
    from Crypto.Util.number import long_to_bytes
except ImportError:
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
                return b'\x00' * padding + ret


def long_to_base64(data, size=0):
    return base64.urlsafe_b64encode(long_to_bytes(data, size)).strip(b'=')


def int_arr_to_long(arr):
    return long(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return int_arr_to_long(struct.unpack('%sB' % len(_d), _d))


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
    hash_digest = hash_alg(access_token.encode('utf-8')).digest()
    cut_at = int(len(hash_digest) / 2)
    truncated = hash_digest[:cut_at]
    at_hash = base64url_encode(truncated)
    return at_hash.decode('utf-8')


def base64url_decode(input):
    """Helper method to base64url_decode a string.

    Args:
        input (str): A base64url_encoded string to decode.

    """
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    """Helper method to base64url_encode a string.

    Args:
        input (str): A base64url_encoded string to encode.

    """
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def timedelta_total_seconds(delta):
    """Helper method to determine the total number of seconds
    from a timedelta.

    Args:
        delta (timedelta): A timedelta to convert to seconds.
    """
    return delta.days * 24 * 60 * 60 + delta.seconds
