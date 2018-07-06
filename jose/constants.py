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
    # RFC8037 - https://tools.ietf.org/html/rfc8037
    EdDSA = 'EdDSA'

    HMAC = {HS256, HS384, HS512}
    RSA = {RS256, RS384, RS512}
    EC = {ES256, ES384, ES512}
    ED = {EdDSA}

    SUPPORTED = HMAC.union(RSA).union(EC).union(ED)

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


ALGORITHMS = Algorithms()


class Usages(object):
    PUBLIC = 'public'
    PRIVATE = 'private'

    SUPPORTED = {PUBLIC, PRIVATE}

    ALL = SUPPORTED


USAGES = Usages()
