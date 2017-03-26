import six

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key, load_pem_public_key, load_der_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from .key import Key, register_algorithm_objects, get_algorithm_object, int_arr_to_long, base64_to_long
from .constants import ALGORITHMS
from .exceptions import JWKError


class RSAKey(Key):
    """
    Performs signing and verification operations using
    RSASSA-PKCS-v1_5 and the specified hash function.
    This class requires cryptography to be installed.
    """

    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, key, algorithm):

        if algorithm not in ALGORITHMS.RSA:
            raise JWKError(
                'hash_alg: %s is not a valid hash algorithm' % algorithm)
        self.hash_alg = get_algorithm_object(algorithm)

        if isinstance(key, rsa.RSAPublicKey) or isinstance(
                key, rsa.RSAPrivateKey):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self._process_jwk(key)
            return

        if isinstance(key, six.string_types):
            if isinstance(key, six.text_type):
                key = key.encode('utf-8')

            if key.startswith(b'-----BEGIN CERTIFICATE-----'):
                try:
                    self._process_cert(key)
                except Exception as e:
                    raise JWKError(e)
                return

            for method, is_private in [(load_der_public_key, False), (
                    load_pem_public_key, False), (load_pem_private_key, True),
                                       (load_der_private_key, True)]:
                try:
                    if is_private:
                        self.prepared_key = method(
                            key, password=None, backend=default_backend())
                    else:
                        self.prepared_key = method(
                            key, backend=default_backend())
                    break
                except Exception as e:
                    continue
            else:
                raise JWKError(
                    'Could not load key using the available methods.')

            return

        raise JWKError('Unable to parse an RSA_JWK from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'RSA':
            raise JWKError("Incorrect key type.  Expected: 'RSA', Recieved: %s"
                           % jwk_dict.get('kty'))

        e = base64_to_long(jwk_dict.get('e', 256))
        n = base64_to_long(jwk_dict.get('n'))

        self.prepared_key = rsa.RSAPublicNumbers(
            e, n).public_key(default_backend())
        return self.prepared_key

    def _process_cert(self, key):

        certSeq = x509.load_pem_x509_certificate(key, default_backend())
        self.prepared_key = certSeq.public_key()

        return

    def sign(self, msg):
        try:
            return self.prepared_key.sign(
                msg,
                padding.PKCS1v15(),
                self.hash_alg(), )
        except Exception as e:
            raise JWKError(e)

    def verify(self, msg, sig):
        try:
            self.prepared_key.verify(
                sig,
                msg,
                padding.PKCS1v15(),
                self.hash_alg(), )

            return True
        except Exception as e:
            return False
