

class ALGORITHMS(object):
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

    HMAC = (HS256, HS384, HS512)
    RSA = (RS256, RS384, RS512)
    EC = (ES256, ES384, ES512)

    SUPPORTED = HMAC + RSA + EC

    ALL = SUPPORTED + (NONE, )
