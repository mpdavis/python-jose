import hashlib
import six

from jose.backends.base import Key
import ecdsa

from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64_to_long


class ECDSAECKey(Key):
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

        self.hash_alg = {
            ALGORITHMS.ES256: self.SHA256,
            ALGORITHMS.ES384: self.SHA384,
            ALGORITHMS.ES512: self.SHA512
        }.get(algorithm)
        self._algorithm = algorithm

        self.curve = self.CURVE_MAP.get(self.hash_alg)

        if isinstance(key, (ecdsa.SigningKey, ecdsa.VerifyingKey)):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            key = key.encode('utf-8')

        if isinstance(key, six.binary_type):
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

    def public_key(self):
        if isinstance(self.prepared_key, ecdsa.VerifyingKey):
            return self
        return self.__class__(self.prepared_key.get_verifying_key(), self._algorithm)

    def to_pem(self):
        return self.prepared_key.to_pem()
