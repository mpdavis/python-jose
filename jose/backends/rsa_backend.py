import rsa as pyrsa
import six

from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64_to_long


class RSAKey(Key):
    SHA256 = 'SHA-256'
    SHA384 = 'SHA-384'
    SHA512 = 'SHA-512'

    def __init__(self, key, algorithm):
        if algorithm not in ALGORITHMS.RSA:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)

        self.hash_alg = {
            ALGORITHMS.RS256: self.SHA256,
            ALGORITHMS.RS384: self.SHA384,
            ALGORITHMS.RS512: self.SHA512
        }.get(algorithm)
        self._algorithm = algorithm

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, (pyrsa.PublicKey, pyrsa.PrivateKey)):
            self._prepared_key = key
            return

        if isinstance(key, six.string_types):
            key = key.encode('utf-8')

        if isinstance(key, six.binary_type):
            try:
                self._prepared_key = pyrsa.PublicKey.load_pkcs1(key)
            except ValueError:
                try:
                    self._prepared_key = pyrsa.PrivateKey.load_pkcs1(key)
                except ValueError as e:
                    raise JWKError(e)
            return
        raise JWKError('Unable to parse an RSA_JWK from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'RSA':
            raise JWKError("Incorrect key type.  Expected: 'RSA', Recieved: %s" % jwk_dict.get('kty'))

        e = base64_to_long(jwk_dict.get('e', 256))
        n = base64_to_long(jwk_dict.get('n'))

        verifying_key = pyrsa.PublicKey(e=e, n=n)
        return verifying_key

    def sign(self, msg):
        print(self._algorithm)
        return pyrsa.sign(msg, self._prepared_key, self.hash_alg)

    def verify(self, msg, sig):
        try:
            return pyrsa.verify(msg, sig, self._prepared_key)
        except pyrsa.pkcs1.VerificationError:
            return False

    def public_key(self):
        if isinstance(self._prepared_key, pyrsa.PublicKey):
            return self
        return self.__class__(pyrsa.PublicKey(n=self._prepared_key.n, e=self._prepared_key.e), self._algorithm)

    def to_pem(self):
        import rsa.pem

        if isinstance(self._prepared_key, rsa.PrivateKey):
            pem = self._prepared_key.save_pkcs1()
        else:
            # this is a PKCS#8 DER header to identify rsaEncryption
            header = b'0\x82\x04\xbd\x02\x01\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00'
            der = self._prepared_key.save_pkcs1(format='DER')
            pem = rsa.pem.save_pem(header + der, pem_marker='PUBLIC KEY')
        return pem
