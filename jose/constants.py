import hashlib


class Algorithms(object):
    NONE = 'none'
    HS256 = 'HS256'
    HS384 = 'HS384'
    HS512 = 'HS512'
    RS256 = 'RS256'
    RS384 = 'RS384'
    RS512 = 'RS512'
    ES256 = 'ES256'
    ES384 = 'ES384'
    ES512 = 'ES512'

    HMAC = set([HS256, HS384, HS512])
    RSA = set([RS256, RS384, RS512])
    EC = set([ES256, ES384, ES512])

    SUPPORTED = HMAC.union(RSA).union(EC)

    ALL = SUPPORTED.union([NONE])

    HASHES = {
        HS256: hashlib.sha256,
        HS384: hashlib.sha384,
        HS512: hashlib.sha512,
        RS256: hashlib.sha256,
        RS384: hashlib.sha384,
        RS512: hashlib.sha512,
        ES256: hashlib.sha256,
        ES384: hashlib.sha384,
        ES512: hashlib.sha512,
    }

    KEYS = {}

    def get_key(self, algorithm):
        from jose.jwk import HMACKey, RSAKey, ECKey
        if algorithm in self.KEYS:
            return self.KEYS[algorithm]
        elif algorithm in self.HMAC:
            return HMACKey
        elif algorithm in self.RSA:
            return RSAKey
        elif algorithm in self.EC:
            return ECKey
        return None

    def register_key(self, algorithm, key_class):
        from jose.jwk import Key
        if issubclass(key_class, Key):
            self.KEYS[algorithm] = key_class
            self.SUPPORTED.add(algorithm)
            return True
        else:
            return False

ALGORITHMS = Algorithms()
