
import base64
import hashlib
import hmac
import struct
import six

from builtins import int

import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import ecdsa

from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.exceptions import JWSError
from jose.exceptions import JOSEError

# PyCryptodome's RSA module doesn't have PyCrypto's _RSAobj class
# Instead it has a class named RsaKey, which serves the same purpose.
if hasattr(RSA, '_RSAobj'):
    _RSAKey = RSA._RSAobj
else:
    _RSAKey = RSA.RsaKey


def get_algorithm_object(algorithm):
    """
    Returns an algorithm object for the given algorithm.
    """

    if algorithm == ALGORITHMS.HS256:
        return HMACKey(HMACKey.SHA256)

    if algorithm == ALGORITHMS.HS384:
        return HMACKey(HMACKey.SHA384)

    if algorithm == ALGORITHMS.HS512:
        return HMACKey(HMACKey.SHA512)

    if algorithm == ALGORITHMS.RS256:
        return RSAKey(RSAKey.SHA256)

    if algorithm == ALGORITHMS.RS384:
        return RSAKey(RSAKey.SHA384)

    if algorithm == ALGORITHMS.RS512:
        return RSAKey(RSAKey.SHA512)

    if algorithm == ALGORITHMS.ES256:
        return ECKey(ECKey.SHA256)

    if algorithm == ALGORITHMS.ES384:
        return ECKey(ECKey.SHA384)

    if algorithm == ALGORITHMS.ES512:
        return ECKey(ECKey.SHA512)

    raise JWSError('Algorithm not supported: %s' % algorithm)


def int_arr_to_long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return int_arr_to_long(struct.unpack('%sB' % len(_d), _d))


class Key(object):
    """
    The interface for an JWK used to sign and verify tokens.
    """
    prepared_key = None

    def process_sign(self, msg, key):
        """
        Processes a signature for the given algorithm.

        This method should be overriden by the implementing algortihm.
        """
        raise NotImplementedError

    def process_verify(self, msg, key, sig):
        """
        Processes a verification for the given algorithm.

        This method should be overriden by the implementing algorithm.
        """
        raise NotImplementedError

    def process_prepare_key(self, key):
        """
        Processes preparing a key for the given algorithm.

        This method should be overriden by the implementing algorithm.
        """
        raise NotImplementedError

    def process_deserialize(self):
        """
        Processes deserializing a key into a JWK JSON format.

        This method should be overriden by the implementing Key class.
        """
        raise NotImplementedError

    def process_jwk(self, jwk):
        """
        Process a JWK dict into a Key object.

        This method shold be overriden by the implementing Key class.
        """
        raise NotImplementedError

    def prepare_key(self, key):
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().

        This is used to catch any library errors and throw a JOSEError.

        Raises:
            TypeError: If an invalid key is attempted to be used.
        """
        try:
            key = self.process_prepare_key(key)
        except Exception as e:
            raise JOSEError(e)

        self.prepared_key = key
        return key

    def sign(self, msg, key):
        """
        Returns a digital signature for the specified message
        using the specified key value.

        This is used to catch any library errors and throw a JOSEError.

        Raises:
            JOSEError: When there is an error creating a signature.
        """
        try:
            return self.process_sign(msg, key)
        except Exception as e:
            raise JOSEError(e)

    def verify(self, msg, key, sig):
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.

        This is used to catch any library errors and throw a JOSEError.

        Raises:
            JOSEError: When there is an error verifiying the signature.
        """
        try:
            return self.process_verify(msg, key, sig)
        except Exception as e:
            raise JOSEError(e)


class HMACKey(Key):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    SHA256 = hashlib.sha256
    SHA384 = hashlib.sha384
    SHA512 = hashlib.sha512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def process_prepare_key(self, key):
        if not isinstance(key, six.string_types) and not isinstance(key, bytes):
            raise TypeError('Expecting a string- or bytes-formatted key.')

        if isinstance(key, six.text_type):
            key = key.encode('utf-8')

        invalid_strings = [
            b'-----BEGIN PUBLIC KEY-----',
            b'-----BEGIN CERTIFICATE-----',
            b'ssh-rsa'
        ]

        if any([string_value in key for string_value in invalid_strings]):
            raise Exception(
                'The specified key is an asymmetric key or x509 certificate and'
                ' should not be used as an HMAC secret.')

        return key

    def process_sign(self, msg, key):
        return hmac.new(key, msg, self.hash_alg).digest()

    def process_verify(self, msg, key, sig):
        return sig == self.sign(msg, key)


class RSAKey(Key):
    """
    Performs signing and verification operations using
    RSASSA-PKCS-v1_5 and the specified hash function.
    This class requires PyCrypto package to be installed.
    This is based off of the implementation in PyJWT 0.3.2
    """
    SHA256 = Crypto.Hash.SHA256
    SHA384 = Crypto.Hash.SHA384
    SHA512 = Crypto.Hash.SHA512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def process_prepare_key(self, key):

        if isinstance(key, (_RSAKey, RSAKey)):
            return key

        if isinstance(key, dict):
            return self.process_jwk(key)

        if isinstance(key, six.string_types):
            if isinstance(key, six.text_type):
                key = key.encode('utf-8')

            key = RSA.importKey(key)
        else:
            raise TypeError('Expecting a PEM- or RSA-formatted key.')

        return key

    def process_jwk(self, jwk):

        if not jwk.get('kty') == 'RSA':
            raise JWKError("Incorrect key type.  Expected: 'RSA', Recieved: %s" % jwk.get('kty'))

        e = base64_to_long(jwk.get('e', 256))
        n = base64_to_long(jwk.get('n'))

        return RSA.construct((n, e))

    def process_sign(self, msg, key):
        return PKCS1_v1_5.new(key).sign(self.hash_alg.new(msg))

    def process_verify(self, msg, key, sig):
        return PKCS1_v1_5.new(key).verify(self.hash_alg.new(msg), sig)


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

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def process_prepare_key(self, key):

        if isinstance(key, ecdsa.SigningKey) or \
           isinstance(key, ecdsa.VerifyingKey):
            return key

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

        else:
            raise TypeError('Expecting a PEM-formatted key.')

        return key

    def process_sign(self, msg, key):
        return key.sign(msg, hashfunc=self.hash_alg, sigencode=ecdsa.util.sigencode_string)

    def process_verify(self, msg, key, sig):
        try:
            return key.verify(sig, msg, hashfunc=self.hash_alg, sigdecode=ecdsa.util.sigdecode_string)
        except:
            return False
