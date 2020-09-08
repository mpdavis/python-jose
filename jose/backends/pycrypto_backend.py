from base64 import b64encode
from binascii import unhexlify

import six
import warnings

import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
from Crypto import Random

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.asn1 import DerSequence

from .base import Key
from ._asn1 import rsa_public_key_pkcs8_to_pkcs1
from ..utils import base64_to_long, long_to_base64
from ..constants import ALGORITHMS
from ..exceptions import JWKError, JWEError, JWEAlgorithmUnsupportedError
from ..utils import base64url_decode


# We default to using PyCryptodome, however, if PyCrypto is installed, it is
# used instead. This is so that environments that require the use of PyCrypto
# are still supported.
if hasattr(RSA, 'RsaKey'):
    _RSAKey = RSA.RsaKey
else:
    _RSAKey = RSA._RSAobj

if not hasattr(AES, "MODE_GCM"):
    # PyCrypto does not support GCM mode
    for gcm_alg in ALGORITHMS.GCM:
        ALGORITHMS.SUPPORTED.remove(gcm_alg)


def get_random_bytes(num_bytes):
    return bytes(Random.new().read(num_bytes))


def _der_to_pem(der_key, marker):
    """
    Perform a simple DER to PEM conversion.
    """
    pem_key_chunks = [('-----BEGIN %s-----' % marker).encode('utf-8')]

    # Limit base64 output lines to 64 characters by limiting input lines to 48 characters.
    for chunk_start in range(0, len(der_key), 48):
        pem_key_chunks.append(b64encode(der_key[chunk_start:chunk_start + 48]))

    pem_key_chunks.append(('-----END %s-----' % marker).encode('utf-8'))

    return b'\n'.join(pem_key_chunks)


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
    SHA1 = Crypto.Hash.SHA if hasattr(Crypto.Hash, "SHA") else Crypto.Hash.SHA1

    def __init__(self, key, algorithm):

        if algorithm not in ALGORITHMS.RSA:
            raise JWKError('hash_alg: %s is not a valid hash algorithm' % algorithm)

        self.hash_alg = {
            ALGORITHMS.RS256: self.SHA256,
            ALGORITHMS.RS384: self.SHA384,
            ALGORITHMS.RS512: self.SHA512,
            ALGORITHMS.RSA1_5: self.SHA1,
            ALGORITHMS.RSA_OAEP: self.SHA1,
            ALGORITHMS.RSA_OAEP_256: self.SHA256,
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
            raise JWKError("Incorrect key type. Expected: 'RSA', Received: %s" % jwk_dict.get('kty'))

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
            return PKCS1_v1_5_Signature.new(self.prepared_key).sign(self.hash_alg.new(msg))
        except Exception as e:
            raise JWKError(e)

    def verify(self, msg, sig):
        if not self.is_public():
            warnings.warn("Attempting to verify a message with a private key. "
                          "This is not recommended.")
        try:
            return PKCS1_v1_5_Signature.new(self.prepared_key).verify(self.hash_alg.new(msg), sig)
        except Exception:
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
            # PyCrypto/dome always export public keys as PKCS8
            if pkcs == 8:
                pem = self.prepared_key.exportKey('PEM')
            else:
                pkcs8_der = self.prepared_key.exportKey('DER')
                pkcs1_der = rsa_public_key_pkcs8_to_pkcs1(pkcs8_der)
                pem = _der_to_pem(pkcs1_der, 'RSA PUBLIC KEY')
            return pem
        else:
            pem = self.prepared_key.exportKey('PEM', pkcs=pkcs)
        return pem

    def to_dict(self):
        data = {
            'alg': self._algorithm,
            'kty': 'RSA',
            'n': long_to_base64(self.prepared_key.n).decode('utf-8'),
            'e': long_to_base64(self.prepared_key.e).decode('utf-8'),
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
                'd': long_to_base64(self.prepared_key.d).decode('utf-8'),
                'p': long_to_base64(self.prepared_key.q).decode('utf-8'),
                'q': long_to_base64(self.prepared_key.p).decode('utf-8'),
                'dp': long_to_base64(dq).decode('utf-8'),
                'dq': long_to_base64(dp).decode('utf-8'),
                'qi': long_to_base64(self.prepared_key.u).decode('utf-8'),
            })

        return data

    def wrap_key(self, key_data):
        try:
            if self._algorithm == ALGORITHMS.RSA1_5:
                cipher = PKCS1_v1_5_Cipher.new(self.prepared_key)
            else:
                cipher = PKCS1_OAEP.new(self.prepared_key, self.hash_alg)
            wrapped_key = cipher.encrypt(key_data)
            return wrapped_key
        except Exception as e:
            raise JWKError(e)

    def unwrap_key(self, wrapped_key):
        try:
            if self._algorithm == ALGORITHMS.RSA1_5:
                sentinel = Random.new().read(32)
                cipher = PKCS1_v1_5_Cipher.new(self.prepared_key)
                plain_text = cipher.decrypt(wrapped_key, sentinel)
            else:
                cipher = PKCS1_OAEP.new(self.prepared_key, self.hash_alg)
                plain_text = cipher.decrypt(wrapped_key)
            return plain_text
        except Exception as e:
            raise JWEError(e)


class AESKey(Key):
    ALG_128 = (ALGORITHMS.A128GCM, ALGORITHMS.A128CBC_HS256, ALGORITHMS.A128GCMKW, ALGORITHMS.A128KW)
    ALG_192 = (ALGORITHMS.A192GCM, ALGORITHMS.A192CBC_HS384, ALGORITHMS.A192GCMKW, ALGORITHMS.A192KW)
    ALG_256 = (ALGORITHMS.A256GCM, ALGORITHMS.A256CBC_HS512, ALGORITHMS.A256GCMKW, ALGORITHMS.A256KW)

    AES_KW_ALGS = (ALGORITHMS.A128KW, ALGORITHMS.A192KW, ALGORITHMS.A256KW)

    MODES = {
        ALGORITHMS.A128CBC_HS256: AES.MODE_CBC,
        ALGORITHMS.A192CBC_HS384: AES.MODE_CBC,
        ALGORITHMS.A256CBC_HS512: AES.MODE_CBC,
        ALGORITHMS.A128CBC: AES.MODE_CBC,
        ALGORITHMS.A192CBC: AES.MODE_CBC,
        ALGORITHMS.A256CBC: AES.MODE_CBC,
        ALGORITHMS.A128KW: AES.MODE_ECB,
        ALGORITHMS.A192KW: AES.MODE_ECB,
        ALGORITHMS.A256KW: AES.MODE_ECB
    }
    if hasattr(AES, "MODE_GCM"):
        #  pycrypto does not support GCM. pycryptdome does
        MODES.update({
            ALGORITHMS.A128GCMKW: AES.MODE_GCM,
            ALGORITHMS.A192GCMKW: AES.MODE_GCM,
            ALGORITHMS.A256GCMKW: AES.MODE_GCM,
            ALGORITHMS.A128GCM: AES.MODE_GCM,
            ALGORITHMS.A192GCM: AES.MODE_GCM,
            ALGORITHMS.A256GCM: AES.MODE_GCM,
        })

    def __init__(self, key, algorithm):
        if algorithm not in ALGORITHMS.AES:
            raise JWKError('%s is not a valid AES algorithm' % algorithm)
        if algorithm not in ALGORITHMS.SUPPORTED.union(ALGORITHMS.AES_PSEUDO):
            raise JWKError('%s is not a supported algorithm' % algorithm)

        self._algorithm = algorithm
        self._mode = self.MODES.get(self._algorithm)
        if self._mode is None:
            raise JWEAlgorithmUnsupportedError("AES Mode is not supported by cryptographic library")

        if algorithm in self.ALG_128 and len(key) != 16:
            raise JWKError("Key must be 128 bits for alg {}".format(algorithm))
        elif algorithm in self.ALG_192 and len(key) != 24:
            raise JWKError("Key must be 192 bits for alg {}".format(algorithm))
        elif algorithm in self.ALG_256 and len(key) != 32:
            raise JWKError("Key must be 256 bits for alg {}".format(algorithm))

        self._key = six.ensure_binary(key)

    def to_dict(self):
        data = {
            'alg': self._algorithm,
            'kty': 'oct',
            'k': self._key
        }
        return data

    def encrypt(self, plain_text, aad=None):
        plain_text = six.ensure_binary(plain_text)
        try:
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self._key, self._mode, iv)
            if self._mode == AES.MODE_CBC:
                padded_plain_text = self._pad(AES.block_size, plain_text)
                cipher_text = cipher.encrypt(padded_plain_text)
                auth_tag = None
            else:
                cipher.update(aad)
                cipher_text, auth_tag = cipher.encrypt_and_digest(plain_text)
            return iv, cipher_text, auth_tag
        except Exception as e:
            raise JWEError(e)

    def decrypt(self, cipher_text, iv=None, aad=None, tag=None):
        cipher_text = six.ensure_binary(cipher_text)
        try:
            cipher = AES.new(self._key, self._mode, iv)
            if self._mode == AES.MODE_CBC:
                padded_plain_text = cipher.decrypt(cipher_text)
                plain_text = self._unpad(padded_plain_text)
            else:
                cipher.update(aad)
                try:
                    plain_text = cipher.decrypt_and_verify(cipher_text, tag)
                except ValueError:
                    raise JWEError("Invalid JWE Auth Tag")

            return plain_text
        except Exception as e:
            raise JWEError(e)

    DEFAULT_IV = unhexlify("A6A6A6A6A6A6A6A6")

    def wrap_key(self, key_data):
        key_data = six.ensure_binary(key_data)

        # AES(K, W)     Encrypt W using the AES codebook with key K
        def aes(k_, w_):
            return AES.new(k_, AES.MODE_ECB).encrypt(w_)

        # MSB(j, W)     Return the most significant j bits of W
        msb = self._most_significant_bits

        # LSB(j, W)     Return the least significant j bits of W
        lsb = self._least_significant_bits

        # B1 ^ B2       The bitwise exclusive or (XOR) of B1 and B2
        # B1 | B2       Concatenate B1 and B2

        # K             The key-encryption key K
        k = self._key

        # n             The number of 64-bit key data blocks
        n = len(key_data) // 8

        # P[i]          The ith plaintext key data block
        p = [None] + [key_data[i * 8:i * 8 + 8] for i in range(n)]  # Split into 8 byte blocks and prepend the 0th item

        # C[i]          The ith ciphertext data block
        c = [None] + [None for _ in range(n)]  # Initialize c with n items and prepend the 0th item

        # A             The 64-bit integrity check register
        a = None

        # R[i]          An array of 64-bit registers where
        #                        i = 0, 1, 2, ..., n
        r = [None] + [None for _ in range(n)]  # Initialize r with n items and prepend the 0th item

        # A[t], R[i][t] The contents of registers A and R[i] after encryption
        #                        step t.

        # IV            The 64-bit initial value used during the wrapping
        #                        process.
        iv = self.DEFAULT_IV

        # 1) Initialize variables.

        # Set A = IV, an initial value
        a = iv
        # For i = 1 to n
        for i in range(1, n + 1):
            # R[i] = P[i]
            r[i] = p[i]

        # 2) Calculate intermediate values.
        #  For j = 0 to 5
        for j in range(6):
            # For i=1 to n
            for i in range(1, n + 1):
                # B = AES(K, A | R[i])
                b = aes(k, a + r[i])
                # A = MSB(64, B) ^ t where t = (n*j)+i
                t = (n * j) + i
                a = msb(64, b)
                a = a[:7] + six.int2byte(six.byte2int([a[7]]) ^ t)
                # R[i] = LSB(64, B)
                r[i] = lsb(64, b)

        # 3) Output the results.
        # Set C[0] = A
        c[0] = a
        # For i = 1 to n
        for i in range(1, n + 1):
            # C[i] = R[i]
            c[i] = r[i]

        cipher_text = b"".join(c)  # Join the chunks to return
        return cipher_text  # IV, cipher text, auth tag

    def unwrap_key(self, wrapped_key):
        wrapped_key = six.ensure_binary(wrapped_key)

        # AES-1(K, W)   Decrypt W using the AES codebook with key K
        def aes_1(k_, w_):
            return AES.new(k_, AES.MODE_ECB).decrypt(w_)

        # MSB(j, W)     Return the most significant j bits of W
        msb = self._most_significant_bits

        # LSB(j, W)     Return the least significant j bits of W
        lsb = self._least_significant_bits

        # B1 ^ B2       The bitwise exclusive or (XOR) of B1 and B2
        # B1 | B2       Concatenate B1 and B2

        # K             The key-encryption key K
        k = self._key

        # n             The number of 64-bit key data blocks
        n = len(wrapped_key) // 8 - 1

        # P[i]          The ith plaintext key data block
        p = [None] + [None] * n  # Initialize p with n items and prepend the 0th item

        # C[i]          The ith ciphertext data block
        c = [wrapped_key[i*8:i*8+8] for i in range(n + 1)]  # Split ciphertext into 8 byte chunks

        # A             The 64-bit integrity check register
        a = None

        # R[i]          An array of 64-bit registers where
        #                        i = 0, 1, 2, ..., n
        r = [None] + [None] * n  # Initialize r with n items and prepend the 0th item

        # A[t], R[i][t] The contents of registers A and R[i] after encryption
        #                        step t.

        # 1) Initialize variables.
        # Set A = C[0]
        a = c[0]
        # For i = 1 to n
        for i in range(1, n + 1):
            # R[i] = C[i]
            r[i] = c[i]

        # 2) Compute intermediate values.
        # For j = 5 to 0
        for j in range(5, -1, -1):
            # For i = n to 1
            for i in range(n, 0, -1):
                # B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                t = n * j + i
                a = a[:7] + six.int2byte(six.byte2int([a[7]]) ^ t)
                b = aes_1(k, a + r[i])
                # A = MSB(64, B)
                a = msb(64, b)
                # R[i] = LSB(64, B)
                r[i] = lsb(64, b)

        # 3) Output results.
        # If A is an appropriate initial value (see 2.2.3),
        if a == self.DEFAULT_IV:
            # Then
            # For i = 1 to n
            for i in range(1, n + 1):
                # P[i] = R[i]
                p[i] = r[i]
        # Else
        else:
            # Return an error
            raise JWEError("Invalid AES Keywrap")

        return b"".join(p[1:])  # Join the chunks and return

    @staticmethod
    def _most_significant_bits(number_of_bits, _bytes):
        number_of_bytes = number_of_bits // 8
        msb = _bytes[:number_of_bytes]
        return msb

    @staticmethod
    def _least_significant_bits(number_of_bits, _bytes):
        number_of_bytes = number_of_bits // 8
        lsb = _bytes[-number_of_bytes:]
        return lsb

    @staticmethod
    def _pad(block_size, unpadded):
        padding_bytes = block_size - len(unpadded) % block_size
        padding = bytes(bytearray([padding_bytes]) * padding_bytes)
        return unpadded + padding

    @staticmethod
    def _unpad(padded):
        padded = six.ensure_binary(padded)
        padding_byte = padded[-1]
        if isinstance(padded, six.string_types):
            padding_byte = ord(padding_byte)
        if padded[-padding_byte:] != bytearray([padding_byte]) * padding_byte:
            raise ValueError("Invalid padding!")
        return padded[:-padding_byte]
