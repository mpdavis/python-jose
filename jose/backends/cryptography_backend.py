import six
import ecdsa
from ecdsa.util import sigdecode_string, sigencode_string, sigdecode_der, sigencode_der

from jose.jwk import Key, base64_to_long
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class CryptographyECKey(Key):
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    CURVE_MAP = {
        SHA256: ec.SECP256R1,
        SHA384: ec.SECP384R1,
        SHA512: ec.SECP521R1,
    }

    def __init__(self, key, algorithm, cryptography_backend=default_backend):
        if algorithm not in ALGORITHMS.EC:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)

        self.hash_alg = {
            ALGORITHMS.ES256: self.SHA256,
            ALGORITHMS.ES384: self.SHA384,
            ALGORITHMS.ES512: self.SHA512
        }.get(algorithm)

        self.curve = self.CURVE_MAP.get(self.hash_alg)
        self.cryptography_backend = cryptography_backend

        if isinstance(key, (ecdsa.SigningKey, ecdsa.VerifyingKey)):
            # convert to PEM and let cryptography below load it as PEM
            key = key.to_pem().decode('utf-8')

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            if isinstance(key, six.text_type):
                key = key.encode('utf-8')

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

        ec_pn = ec.EllipticCurvePublicNumbers(x, y, self.curve())
        verifying_key = ec_pn.public_key(self.cryptography_backend())

        return verifying_key

    def sign(self, msg):
        signature = self.prepared_key.sign(msg, ec.ECDSA(self.hash_alg()))
        order = (2 ** self.curve.key_size) - 1
        return sigencode_string(*sigdecode_der(signature, order), order=order)

    def verify(self, msg, sig):
        order = (2 ** self.curve.key_size) - 1
        signature = sigencode_der(*sigdecode_string(sig, order), order=order)
        verifier = self.prepared_key.verifier(signature, ec.ECDSA(self.hash_alg()))
        verifier.update(msg)
        try:
            return verifier.verify()
        except:
            return False


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

        self.cryptography_backend = cryptography_backend

        if isinstance(key, _RSAPublicKey):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            if isinstance(key, six.text_type):
                key = key.encode('utf-8')

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
