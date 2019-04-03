import base64

import six

from jose.backends.base import Key
from jose.constants import ALGORITHMS, USAGES
from jose.exceptions import JWKError

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class Ed25519Key(Key):
    def __init__(self, key, algorithm, use=None):
        if algorithm not in ALGORITHMS.ED:
            raise JWKError('hash_alg: %s is not a valid Ed25519 hash algorithm' % algorithm)

        # TODO: Validate Ed25519 hash algorithms
        self._algorithm = algorithm

        if isinstance(key, dict):
            self._prepared_key = self._process_jwk(key)
            return

        if isinstance(key, (SigningKey, VerifyKey)):
            self._prepared_key = key
            return

        if isinstance(key, six.string_types):
            key = key.encode('utf-8') + b'=='

        if isinstance(key, six.binary_type):
            if use is None:
                raise JWKError("The 'use' parameter is required when deserializing an Ed25519 key "
                               "from a string or bytes")

            if use == USAGES.PUBLIC:
                decoded_key_bytes = base64.urlsafe_b64decode(key)
                self._prepared_key = VerifyKey(decoded_key_bytes)
            elif use == USAGES.PRIVATE:
                decoded_key_bytes = base64.urlsafe_b64decode(key)
                self._prepared_key = SigningKey(decoded_key_bytes)
            else:
                raise JWKError("The 'use' parameter must either be 'public' or 'private', not %s" % use)
            return

        raise JWKError('Unable to parse an Ed25519_JWK from key: %s' % key)

    def _process_jwk(self, jwk_dict):
        if not jwk_dict.get('kty') == 'OKP':
            raise JWKError("Incorrect key type.  Expected: 'OKP', Received: %s" % jwk_dict.get('kty'))

        if not jwk_dict.get('crv') == 'Ed25519':
            raise JWKError("Incorrect key subtype.  Expected 'Ed25519', Received %s" % jwk_dict.get('crv'))

        if 'd' in jwk_dict:
            # d indicates private key
            d = jwk_dict.get('d').encode('utf-8') + b'=='
            decoded_d_bytes = base64.urlsafe_b64decode(d)
            return SigningKey(decoded_d_bytes)
        else:
            # no d indicates public key
            x = jwk_dict.get('x').encode('utf-8') + b'=='
            decoded_x_bytes = base64.urlsafe_b64decode(x)
            return VerifyKey(decoded_x_bytes)

    def sign(self, msg):
        if isinstance(msg, six.string_types):
            msg = msg.encode('utf-8')
        return self._prepared_key.sign(msg)

    def verify(self, msg, sig=None):
        try:
            self._prepared_key.verify(msg, sig)
            return True
        except BadSignatureError:
            return False

    def is_public(self):
        return isinstance(self._prepared_key, VerifyKey)

    def public_key(self):
        if isinstance(self._prepared_key, VerifyKey):
            return self
        return self.__class__(self._prepared_key.verify_key, self._algorithm)

    def to_pem(self, *args, **kwargs):
        # Serializing Ed25519 keys is not yet supported anywhere in Python
        # AFAICT, so instead of creating our own format, we simply prevent
        # anybody from serializing to PEM.
        raise NotImplementedError("Cannot serialize Ed25519 keys yet")

    def to_dict(self):
        public_key = self.public_key()

        data = {
            'alg': self._algorithm,
            'kty': 'OKP',
            'crv': 'Ed25519',
            'x': base64.urlsafe_b64encode(bytes(public_key._prepared_key)).decode('utf-8'),
        }

        if not self.is_public():
            data.update({'d': base64.urlsafe_b64encode(bytes(self._prepared_key)).decode('utf-8')})

        return data
