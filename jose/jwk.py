
import hashlib
import hmac
import six

from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode, base64url_encode
from jose.utils import constant_time_string_compare
from jose.backends.base import Key

try:
    from jose.backends import RSAKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import ECKey  # noqa: F401
except ImportError:
    pass


def get_key(algorithm):
    if algorithm in ALGORITHMS.KEYS:
        return ALGORITHMS.KEYS[algorithm]
    elif algorithm in ALGORITHMS.HMAC:
        return HMACKey
    elif algorithm in ALGORITHMS.RSA:
        from jose.backends import RSAKey  # noqa: F811
        return RSAKey
    elif algorithm in ALGORITHMS.EC:
        from jose.backends import ECKey  # noqa: F811
        return ECKey
    return None


def register_key(algorithm, key_class):
    if not issubclass(key_class, Key):
        raise TypeError("Key class not a subclass of jwk.Key")
    ALGORITHMS.KEYS[algorithm] = key_class
    ALGORITHMS.SUPPORTED.add(algorithm)
    return True


def construct(key_data, algorithm=None):
    """
    Construct a Key object for the given algorithm with the given
    key_data.
    """

    # Allow for pulling the algorithm off of the passed in jwk.
    if not algorithm and isinstance(key_data, dict):
        algorithm = key_data.get('alg', None)

    if not algorithm:
        raise JWKError('Unable to find a algorithm for key: %s' % key_data)

    key_class = get_key(algorithm)
    if not key_class:
        raise JWKError('Unable to find a algorithm for key: %s' % key_data)
    return key_class(key_data, algorithm)


def get_algorithm_object(algorithm):
    algorithms = {
        ALGORITHMS.HS256: 'SHA256',
        ALGORITHMS.HS384: 'SHA384',
        ALGORITHMS.HS512: 'SHA512',
        ALGORITHMS.RS256: 'SHA256',
        ALGORITHMS.RS384: 'SHA384',
        ALGORITHMS.RS512: 'SHA512',
        ALGORITHMS.ES256: 'SHA256',
        ALGORITHMS.ES384: 'SHA384',
        ALGORITHMS.ES512: 'SHA512',
    }
    key = get_key(algorithm)
    attr = algorithms.get(algorithm, None)
    return getattr(key, attr)


class HMACKey(Key):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    def __init__(self, key, algorithm):
        if algorithm not in ALGORITHMS.HMAC:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)
        self._algorithm = algorithm
        self.hash_alg = get_algorithm_object(algorithm)

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if not isinstance(key, six.string_types) and not isinstance(key, bytes):
            raise JWKError('Expecting a string- or bytes-formatted key.')

        if isinstance(key, six.text_type):
            key = key.encode('utf-8')

        invalid_strings = [
            b'-----BEGIN PUBLIC KEY-----',
            b'-----BEGIN RSA PUBLIC KEY-----',
            b'-----BEGIN CERTIFICATE-----',
            b'ssh-rsa'
        ]

        if any(string_value in key for string_value in invalid_strings):
            raise JWKError(
                'The specified key is an asymmetric key or x509 certificate and'
                ' should not be used as an HMAC secret.')

        self.prepared_key = key

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'oct':
            raise JWKError("Incorrect key type.  Expected: 'oct', Recieved: %s" % jwk_dict.get('kty'))

        k = jwk_dict.get('k')
        k = k.encode('utf-8')
        k = bytes(k)
        k = base64url_decode(k)

        return k

    def sign(self, msg):
        return hmac.new(self.prepared_key, msg, self.hash_alg).digest()

    def verify(self, msg, sig):
        return constant_time_string_compare(sig, self.sign(msg))

    def to_dict(self):
        return {
            'alg': self._algorithm,
            'kty': 'oct',
            'k': base64url_encode(self.prepared_key),
        }
