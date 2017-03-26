
import base64
import hashlib
import hmac
import struct
import six
import sys

import ecdsa

from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode
from jose.utils import constant_time_string_compare
from .key import Key, register_algorithm_objects, get_algorithm_object, int_arr_to_long, base64_to_long

try:
    from .cryptphy import RSAKey
except ImportError:
    from .pycrypto import RSAKey

# Deal with integer compatibilities between Python 2 and 3.
# Using `from builtins import int` is not supported on AppEngine.
if sys.version_info > (3,):
    long = int


def get_key(algorithm):
    if algorithm in ALGORITHMS.KEYS:
        return ALGORITHMS.KEYS[algorithm]
    elif algorithm in ALGORITHMS.HMAC:
        return HMACKey
    elif algorithm in ALGORITHMS.RSA:
        return RSAKey
    elif algorithm in ALGORITHMS.EC:
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
            b'-----BEGIN CERTIFICATE-----',
            b'ssh-rsa'
        ]

        if any([string_value in key for string_value in invalid_strings]):
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


class ECKey(Key):
    """
    Performs signing and verification operations using
    ECDSA and the specified hash function

    This class requires the ecdsa package to be installed.

    This is based off of the implementation in PyJWT 0.3.2
    """
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    CURVE_MAP = {
        SHA256: ecdsa.curves.NIST256p,
        SHA384: ecdsa.curves.NIST384p,
        SHA512: ecdsa.curves.NIST521p,
    }

    def __init__(self, key, algorithm):
        if algorithm not in ALGORITHMS.EC:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)
        self.hash_alg = get_algorithm_object(algorithm)

        self.curve = self.CURVE_MAP.get(self.hash_alg)

        if isinstance(key, (ecdsa.SigningKey, ecdsa.VerifyingKey)):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            if isinstance(key, six.text_type):
                key = key.encode('utf-8')

            # Attempt to load key. We don't know if it's
            # a Signing Key or a Verifying Key, so we try
            # the Verifying Key first.
            try:
                key = ecdsa.VerifyingKey.from_pem(key)
            except ecdsa.der.UnexpectedDER:
                key = ecdsa.SigningKey.from_pem(key)
            except Exception as e:
                raise JWKError(e)

            self.prepared_key = key
            return

        raise JWKError('Unable to parse an ECKey from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'EC':
            raise JWKError("Incorrect key type.  Expected: 'EC', Recieved: %s" % jwk_dict.get('kty'))

        x = base64_to_long(jwk_dict.get('x'))
        y = base64_to_long(jwk_dict.get('y'))

        if not ecdsa.ecdsa.point_is_valid(self.curve.generator, x, y):
            raise JWKError("Point: %s, %s is not a valid point" % (x, y))

        point = ecdsa.ellipticcurve.Point(self.curve.curve, x, y, self.curve.order)
        verifying_key = ecdsa.keys.VerifyingKey.from_public_point(point, self.curve)

        return verifying_key

    def sign(self, msg):
        return self.prepared_key.sign(msg, hashfunc=self.hash_alg, sigencode=ecdsa.util.sigencode_string)

    def verify(self, msg, sig):
        try:
            return self.prepared_key.verify(sig, msg, hashfunc=self.hash_alg, sigdecode=ecdsa.util.sigdecode_string)
        except:
            return False


# Registration must be done here to avoid recursive imports.

register_algorithm_objects({
    ALGORITHMS.HS256: HMACKey.SHA256,
    ALGORITHMS.HS384: HMACKey.SHA384,
    ALGORITHMS.HS512: HMACKey.SHA512,
    ALGORITHMS.RS256: RSAKey.SHA256,
    ALGORITHMS.RS384: RSAKey.SHA384,
    ALGORITHMS.RS512: RSAKey.SHA512,
    ALGORITHMS.ES256: ECKey.SHA256,
    ALGORITHMS.ES384: ECKey.SHA384,
    ALGORITHMS.ES512: ECKey.SHA512,
})
