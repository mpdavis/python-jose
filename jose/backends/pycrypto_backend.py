import six

import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.asn1 import DerSequence

from jose.backends.base import Key
from jose.backends.rsa_backend import pem_to_spki
from jose.utils import base64_to_long, long_to_base64
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode


# We default to using PyCryptodome, however, if PyCrypto is installed, it is
# used instead. This is so that environments that require the use of PyCrypto
# are still supported.
if hasattr(RSA, 'RsaKey'):
    _RSAKey = RSA.RsaKey
else:
    _RSAKey = RSA._RSAobj


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
        params = (n, e)

        if 'd' in jwk_dict:
            params += (base64_to_long(jwk_dict.get('d')),)

            extra_params = ['p', 'q', 'dp', 'dq', 'qi']

            if any(k in jwk_dict for k in extra_params):
                # Precomputed private key parameters are available.
                if not all(k in jwk_dict for k in extra_params):
                    # These values must be present when 'p' is according to
                    # Section 6.3.2 of RFC7518, so if they are not we raise
                    # an error.
                    raise JWKError('Precomputed private key parameters are incomplete.')

                p = base64_to_long(jwk_dict.get('p'))
                q = base64_to_long(jwk_dict.get('q'))
                qi = base64_to_long(jwk_dict.get('qi'))

                # PyCrypto does not take the dp and dq as arguments, so we do
                # not pass them. Furthermore, the parameter qi specified in
                # the JWK is the inverse of q modulo p, whereas PyCrypto
                # takes the inverse of p modulo q. We therefore switch the
                # parameters to make the third parameter the inverse of the
                # second parameter modulo the first parameter.
                params += (q, p, qi)

        self.prepared_key = RSA.construct(params)

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

    def is_public(self):
        return not self.prepared_key.has_private()

    def public_key(self):
        if self.is_public():
            return self
        return self.__class__(self.prepared_key.publickey(), self._algorithm)

    def to_pem(self, pem_format='PKCS8'):
        if pem_format == 'PKCS8':
            pkcs = 8
        elif pem_format == 'PKCS1':
            pkcs = 1
        else:
            raise ValueError("Invalid pem format specified: %r" % (pem_format,))

        if self.is_public():
            pem = self.prepared_key.exportKey('PEM', pkcs=1)
            if pkcs == 8:
                pem = pem_to_spki(pem, fmt='PKCS8')
            else:
                pem = pem_to_spki(pem, fmt='PKCS1')
            return pem
        else:
            pem = self.prepared_key.exportKey('PEM', pkcs=pkcs)
        return pem

    def to_dict(self):
        data = {
            'alg': self._algorithm,
            'kty': 'RSA',
            'n': long_to_base64(self.prepared_key.n),
            'e': long_to_base64(self.prepared_key.e),
        }

        if not self.is_public():
            # Section 6.3.2 of RFC7518 prescribes that when we include the
            # optional parameters p and q, we must also include the values of
            # dp and dq, which are not readily available from PyCrypto - so we
            # calculate them. Moreover, PyCrypto stores the inverse of p
            # modulo q rather than the inverse of q modulo p, so we switch
            # p and q. As far as I can tell, this is OK - RFC7518 only
            # asserts that p is the 'first factor', but does not specify
            # what 'first' means in this case.
            dp = self.prepared_key.d % (self.prepared_key.p - 1)
            dq = self.prepared_key.d % (self.prepared_key.q - 1)
            data.update({
                'd': long_to_base64(self.prepared_key.d),
                'p': long_to_base64(self.prepared_key.q),
                'q': long_to_base64(self.prepared_key.p),
                'dp': long_to_base64(dq),
                'dq': long_to_base64(dp),
                'qi': long_to_base64(self.prepared_key.u),
            })

        return data
