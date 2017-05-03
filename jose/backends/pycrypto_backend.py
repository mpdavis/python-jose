import six

import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.asn1 import DerSequence

from jose.backends.base import Key
from jose.utils import base64_to_long
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode

# PyCryptodome's RSA module doesn't have PyCrypto's _RSAobj class
# Instead it has a class named RsaKey, which serves the same purpose.
if hasattr(RSA, '_RSAobj'):
    _RSAKey = RSA._RSAobj
else:
    _RSAKey = RSA.RsaKey


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

    def __init__(self, key, algorithm):

        if algorithm not in ALGORITHMS.RSA:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)

        self.hash_alg = {
            ALGORITHMS.RS256: self.SHA256,
            ALGORITHMS.RS384: self.SHA384,
            ALGORITHMS.RS512: self.SHA512
        }.get(algorithm)
        self._algorithm = algorithm

        if isinstance(key, _RSAKey):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            key = key.encode('utf-8')

        if isinstance(key, six.binary_type):
            if key.startswith(b'-----BEGIN CERTIFICATE-----'):
                try:
                    self._process_cert(key)
                except Exception as e:
                    raise JWKError(e)
                return

            try:
                self.prepared_key = RSA.importKey(key)
            except Exception as e:
                raise JWKError(e)
            return

        raise JWKError('Unable to parse an RSA_JWK from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'RSA':
            raise JWKError("Incorrect key type.  Expected: 'RSA', Recieved: %s" % jwk_dict.get('kty'))

        e = base64_to_long(jwk_dict.get('e', 256))
        n = base64_to_long(jwk_dict.get('n'))

        self.prepared_key = RSA.construct((n, e))
        return self.prepared_key

    def _process_cert(self, key):
        pemLines = key.replace(b' ', b'').split()
        certDer = base64url_decode(b''.join(pemLines[1:-1]))
        certSeq = DerSequence()
        certSeq.decode(certDer)
        tbsSeq = DerSequence()
        tbsSeq.decode(certSeq[0])
        self.prepared_key = RSA.importKey(tbsSeq[6])
        return

    def sign(self, msg):
        try:
            return PKCS1_v1_5.new(self.prepared_key).sign(self.hash_alg.new(msg))
        except Exception as e:
            raise JWKError(e)

    def verify(self, msg, sig):
        try:
            return PKCS1_v1_5.new(self.prepared_key).verify(self.hash_alg.new(msg), sig)
        except Exception as e:
            return False

    def public_key(self):
        if not self.prepared_key.has_private():
            return self
        return self.__class__(self.prepared_key.publickey(), self._algorithm)

    def to_pem(self):
        pem = self.prepared_key.exportKey('PEM', pkcs=1)

        # pycryptodome fix
        begin = b'-----BEGIN RSA PUBLIC KEY-----'
        end = b'-----END RSA PUBLIC KEY-----'
        if pem.startswith(begin) and pem.strip().endswith(end):
            pem = b'-----BEGIN PUBLIC KEY-----' + pem.strip()[len(begin):-len(end)] + b'-----END PUBLIC KEY-----'
        if not pem.endswith(b'\n'):
            pem = pem + b'\n'
        return pem
