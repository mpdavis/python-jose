import six
import ecdsa
from ecdsa.util import sigdecode_string, sigencode_string, sigdecode_der, sigencode_der

from jose.backends.base import Key
from jose.utils import base64_to_long
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

        x = base64_to_long(jwk_dict.get('x'))
        y = base64_to_long(jwk_dict.get('y'))

        curve = {
            'P-256': ec.SECP256R1,
            'P-384': ec.SECP384R1,
            'P-521': ec.SECP521R1,
        }[jwk_dict['crv']]

        ec_pn = ec.EllipticCurvePublicNumbers(x, y, curve())
        verifying_key = ec_pn.public_key(self.cryptography_backend())

        return verifying_key

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
            return verifier.verify()
        except:
            return False

    def public_key(self):
        if hasattr(self.prepared_key, 'public_bytes'):
            return self
        return self.__class__(self.prepared_key.public_key(), self._algorithm)

    def to_pem(self):
        if hasattr(self.prepared_key, 'public_bytes'):
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

        verifying_key = rsa.RSAPublicNumbers(e, n).public_key(self.cryptography_backend())
        return verifying_key

    def sign(self, msg):
        signer = self.prepared_key.signer(
            padding.PKCS1v15(),
            self.hash_alg()
        )
        signer.update(msg)
        signature = signer.finalize()
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

    def public_key(self):
        if hasattr(self.prepared_key, 'public_bytes'):
            return self
        return self.__class__(self.prepared_key.public_key(), self._algorithm)

    def to_pem(self):
        if hasattr(self.prepared_key, 'public_bytes'):
            return self.prepared_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        return self.prepared_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
