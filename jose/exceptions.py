

class JOSEError(Exception):
    pass


class JWSError(JOSEError):
    pass


class JWSSignatureError(JWSError):
    pass


class JWSAlgorithmError(JWSError):
    pass


class JWTError(JOSEError):
    pass


class JWTClaimsError(JWTError):
    pass


class JWTSignatureError(JWTError):
    pass


class ExpiredSignatureError(JWTError):
    pass


class JWKError(JOSEError):
    pass
