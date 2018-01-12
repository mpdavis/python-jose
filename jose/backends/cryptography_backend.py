import six
import ecdsa
from ecdsa.util import sigdecode_string, sigencode_string, sigdecode_der, sigencode_der

from jose.backends.base import Key
from jose.utils import base64_to_long, long_to_base64
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class CryptographyECKey(Key):
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, key, algorithm, cryptography_backend=default_backend):
        if algorithm not in ALGORITHMS.EC:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)

        self.hash_alg = {
            ALGORITHMS.ES256: self.SHA256,
            ALGORITHMS.ES384: self.SHA384,
            ALGORITHMS.ES512: self.SHA512
        }.get(algorithm)
        self._algorithm = algorithm

        self.cryptography_backend = cryptography_backend

        if hasattr(key, 'public_bytes') or hasattr(key, 'private_bytes'):
            self.prepared_key = key
            return

        if isinstance(key, (ecdsa.SigningKey, ecdsa.VerifyingKey)):
            # convert to PEM and let cryptography below load it as PEM
            key = key.to_pem().decode('utf-8')

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            key = key.encode('utf-8')

        if isinstance(key, six.binary_type):
            # Attempt to load key. We don't know if it's
            # a Public Key or a Private Key, so we try
            # the Public Key first.
            try:
                try:
                    key = load_pem_public_key(key, self.cryptography_backend())
                except ValueError:
                    key = load_pem_private_key(key, password=None, backend=self.cryptography_backend())
            except Exception as e:
                raise JWKError(e)

            self.prepared_key = key
            return

        raise JWKError('Unable to parse an ECKey from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'EC':
            raise JWKError("Incorrect key type.  Expected: 'EC', Recieved: %s" % jwk_dict.get('kty'))

        if not all(k in jwk_dict for k in ['x', 'y', 'crv']):
            raise JWKError('Mandatory parameters are missing')

        x = base64_to_long(jwk_dict.get('x'))
        y = base64_to_long(jwk_dict.get('y'))
        curve = {
            'P-256': ec.SECP256R1,
            'P-384': ec.SECP384R1,
            'P-521': ec.SECP521R1,
        }[jwk_dict['crv']]

        public = ec.EllipticCurvePublicNumbers(x, y, curve())

        if 'd' in jwk_dict:
            d = base64_to_long(jwk_dict.get('d'))
            private = ec.EllipticCurvePrivateNumbers(d, public)

            return private.private_key(self.cryptography_backend())
        else:
            return public.public_key(self.cryptography_backend())

    def sign(self, msg):
        if self.hash_alg.digest_size * 8 > self.prepared_key.curve.key_size:
            raise TypeError("this curve (%s) is too short "
                            "for your digest (%d)" % (self.prepared_key.curve.name,
                                                      8*self.hash_alg.digest_size))
        signature = self.prepared_key.sign(msg, ec.ECDSA(self.hash_alg()))
        order = (2 ** self.prepared_key.curve.key_size) - 1
        return sigencode_string(*sigdecode_der(signature, order), order=order)

    def verify(self, msg, sig):
        order = (2 ** self.prepared_key.curve.key_size) - 1
        signature = sigencode_der(*sigdecode_string(sig, order), order=order)
        verifier = self.prepared_key.verifier(signature, ec.ECDSA(self.hash_alg()))
        verifier.update(msg)
        try:
            verifier.verify()
            return True
        except:
            return False

    def is_public(self):
        return hasattr(self.prepared_key, 'public_bytes')

    def public_key(self):
        if self.is_public():
            return self
        return self.__class__(self.prepared_key.public_key(), self._algorithm)

    def to_pem(self):
        if self.is_public():
            pem = self.prepared_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem
        pem = self.prepared_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem

    def to_dict(self):
        if not self.is_public():
            public_key = self.prepared_key.public_key()
        else:
            public_key = self.prepared_key

        crv = {
            'secp256r1': 'P-256',
            'secp384r1': 'P-384',
            'secp521r1': 'P-521',
        }[self.prepared_key.curve.name]

        # Calculate the key size in bytes. Section 6.2.1.2 and 6.2.1.3 of
        # RFC7518 prescribes that the 'x', 'y' and 'd' parameters of the curve
        # points must be encoded as octed-strings of this length.
        key_size = (self.prepared_key.curve.key_size + 7) // 8

        data = {
            'alg': self._algorithm,
            'kty': 'EC',
            'crv': crv,
            'x': long_to_base64(public_key.public_numbers().x, size=key_size),
            'y': long_to_base64(public_key.public_numbers().y, size=key_size),
        }

        if not self.is_public():
            data['d'] = long_to_base64(
                self.prepared_key.private_numbers().private_value,
                size=key_size
            )

        return data


class CryptographyRSAKey(Key):
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, key, algorithm, cryptography_backend=default_backend):
        if algorithm not in ALGORITHMS.RSA:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)

        self.hash_alg = {
            ALGORITHMS.RS256: self.SHA256,
            ALGORITHMS.RS384: self.SHA384,
            ALGORITHMS.RS512: self.SHA512
        }.get(algorithm)
        self._algorithm = algorithm

        self.cryptography_backend = cryptography_backend

        # if it conforms to RSAPublicKey interface
        if hasattr(key, 'public_bytes') and hasattr(key, 'public_numbers'):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            key = key.encode('utf-8')

        if isinstance(key, six.binary_type):
            try:
                try:
                    key = load_pem_public_key(key, self.cryptography_backend())
                except ValueError:
                    key = load_pem_private_key(key, password=None, backend=self.cryptography_backend())
                self.prepared_key = key
            except Exception as e:
                raise JWKError(e)
            return

        raise JWKError('Unable to parse an RSA_JWK from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'RSA':
            raise JWKError("Incorrect key type.  Expected: 'RSA', Recieved: %s" % jwk_dict.get('kty'))

        e = base64_to_long(jwk_dict.get('e', 256))
        n = base64_to_long(jwk_dict.get('n'))
        public = rsa.RSAPublicNumbers(e, n)

        if 'd' not in jwk_dict:
            return public.public_key(self.cryptography_backend())
        else:
            # This is a private key.
            d = base64_to_long(jwk_dict.get('d'))

            extra_params = ['p', 'q', 'dp', 'dq', 'qi']

            if any(k in jwk_dict for k in extra_params):
                # Precomputed private key parameters are available.
                if not all(k in jwk_dict for k in extra_params):
                    # These values must be present when 'p' is according to
                    # Section 6.3.2 of RFC7518, so if they are not we raise
                    # an error.
                    raise JWKError('Precomputed private key parameters are incomplete.')

                p = base64_to_long(jwk_dict['p'])
                q = base64_to_long(jwk_dict['q'])
                dp = base64_to_long(jwk_dict['dp'])
                dq = base64_to_long(jwk_dict['dq'])
                qi = base64_to_long(jwk_dict['qi'])
            else:
                # The precomputed private key parameters are not available,
                # so we use cryptography's API to fill them in.
                p, q = rsa.rsa_recover_prime_factors(n, e, d)
                dp = rsa.rsa_crt_dmp1(d, p)
                dq = rsa.rsa_crt_dmq1(d, q)
                qi = rsa.rsa_crt_iqmp(p, q)

            private = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public)

            return private.private_key(self.cryptography_backend())

    def sign(self, msg):
        try:
            signer = self.prepared_key.signer(
                padding.PKCS1v15(),
                self.hash_alg()
            )
            signer.update(msg)
            signature = signer.finalize()
        except Exception as e:
            raise JWKError(e)
        return signature

    def verify(self, msg, sig):
        verifier = self.prepared_key.verifier(
            sig,
            padding.PKCS1v15(),
            self.hash_alg()
        )
        verifier.update(msg)
        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    def is_public(self):
        return hasattr(self.prepared_key, 'public_bytes')

    def public_key(self):
        if self.is_public():
            return self
        return self.__class__(self.prepared_key.public_key(), self._algorithm)

    def to_pem(self):
        if self.is_public():
            return self.prepared_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        return self.prepared_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def to_dict(self):
        if not self.is_public():
            public_key = self.prepared_key.public_key()
        else:
            public_key = self.prepared_key

        data = {
            'alg': self._algorithm,
            'kty': 'RSA',
            'n': long_to_base64(public_key.public_numbers().n),
            'e': long_to_base64(public_key.public_numbers().e),
        }

        if not self.is_public():
            data.update({
                'd': long_to_base64(self.prepared_key.private_numbers().d),
                'p': long_to_base64(self.prepared_key.private_numbers().p),
                'q': long_to_base64(self.prepared_key.private_numbers().q),
                'dp': long_to_base64(self.prepared_key.private_numbers().dmp1),
                'dq': long_to_base64(self.prepared_key.private_numbers().dmq1),
                'qi': long_to_base64(self.prepared_key.private_numbers().iqmp),
            })

        return data
