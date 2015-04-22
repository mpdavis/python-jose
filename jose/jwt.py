
from calendar import timegm
from datetime import datetime
from datetime import timedelta
from six import string_types

from jose import jws

from .utils import timedelta_total_seconds


def encode(claims, key, algorithm=None):
    """Encodes a claims set and returns a JWT string.

    JWTs are JWS signed objects with a few reserved claims.

    Examples:

        >>> jwt.encode({'a': 'b'}, 'secret', algorithm='HS256')
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'

    Args:
        claims (dict): A claims set to sign
        key (str): The key to use for signing the claim set
        headers (dict, optional): A set of headers that will be added to
            the default headers.  Any headers that are added as additional
            headers will override the default headers.
        algorithm (str, optional): The algorithm to use for signing the
            the claims.  Defaults to HS256.

    Returns:
        str: The string representation of the header, claims, and signature.

    Raises:
        Exception: If there is an error encoding the claims.

    """

    for time_claim in ['exp', 'iat', 'nbf']:

        # Convert datetime to a intDate value in known time-format claims
        if isinstance(claims.get(time_claim), datetime):
            claims[time_claim] = timegm(claims[time_claim].utctimetuple())

    return jws.sign(claims, key)


def decode(token, key, algorithms=None, options=None, audience=None, issuer=None):
    """Verifies a JWT string's signature and validates reserved claims.

    Examples:

        >>> payload = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        >>> jwt.decode(payload, 'secret', algorithms='HS256')

    Args:
        token (str): A signed JWS to be verified.
        key (str): A key to attempt to verify the payload with.
        algorithms (str or list): Valid algorithms that should be used to verify the JWS.
        audience (str): The intended audience of the token.  If the "aud" claim is
            included in the claim set, then the audience must be included and must equal
            the provided claim.
        issuer (str): The issuer of the token.  If the "iss" claim is
            included in the claim set, then the issuer must be included and must equal
            the provided claim.
        options (dict): A dictionary of options for skipping validation steps.

            default = {
                'verify_signature': True,
                'verify_aud': True,
                'verify_iat': True,
                'verify_exp': True,
                'verify_nbf': True,
                'leeway': 0,
            }

    Returns:
        dict: The dict representation of the claims set, assuming the signature is valid
            and all requested data validation passes.

    Raises:
        Exception: If the signature is invalid in any way.

    """

    defaults = {
        'verify_signature': True,
        'verify_aud': True,
        'verify_iat': True,
        'verify_exp': True,
        'verify_nbf': True,
        'leeway': 0,
    }

    if options:
        defaults.update(options)

    # TODO: skip verification for verify_signature == False
    token_info = jws.verify(token, key, algorithms)

    _validate_claims(token_info, audience=audience, issuer=issuer, options=defaults)

    return token_info


def _validate_claims(payload, audience=None, issuer=None, options=None):

    leeway = options.get('leeway', 0)

    if isinstance(leeway, timedelta):
        leeway = timedelta_total_seconds(leeway)

    if not isinstance(audience, (string_types, type(None))):
        raise TypeError('audience must be a string or None')

    now = timegm(datetime.utcnow().utctimetuple())

    if 'iat' in payload and options.get('verify_iat'):
        try:
            iat = int(payload['iat'])
        except ValueError:
            raise Exception('Issued At claim (iat) must be an integer.')

        if iat > (now + leeway):
            raise Exception('Issued At claim (iat) cannot be in the future.')

    if 'nbf' in payload and options.get('verify_nbf'):
        try:
            nbf = int(payload['nbf'])
        except ValueError:
            raise Exception('Not Before claim (nbf) must be an integer.')

        if nbf > (now + leeway):
            raise Exception('The token is not yet valid (nbf)')

    if 'exp' in payload and options.get('verify_exp'):
        try:
            exp = int(payload['exp'])
        except ValueError:
            raise Exception('Expiration Time claim (exp) must be an integer.')

        if exp < (now - leeway):
            raise Exception('Signature has expired')

    if 'aud' in payload and options.get('verify_aud'):
        audience_claims = payload['aud']
        if isinstance(audience_claims, string_types):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise Exception('Invalid claim format in token')
        if any(not isinstance(c, string_types) for c in audience_claims):
            raise Exception('Invalid claim format in token')
        if audience not in audience_claims:
            raise Exception('Invalid audience')
    elif audience is not None:
        # Application specified an audience, but it could not be
        # verified since the token does not contain a claim.
        raise Exception('No audience claim in token')

    if issuer is not None:
        if payload.get('iss') != issuer:
            raise Exception('Invalid issuer')
