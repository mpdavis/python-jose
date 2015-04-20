
import json

from .algorithms import get_algorithm_object
from .constants import ALGORITHMS
from .utils import base64url_encode
from .utils import base64url_decode


def sign(claims, key, headers=None, algorithm=ALGORITHMS.HS256):
    """Signs a claims set and returns a JWS string.

    Examples:

        >>> jws.sign({'a': 'b'}, 'secret', algorithm='HS256')
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
        Exception: If there is an error signing the claims.

    """

    if algorithm not in ALGORITHMS.SUPPORTED:
        raise Exception('Algorithm %s not supported.' % algorithm)

    encoded_header = _encode_header(algorithm, additional_headers=headers)
    encoded_claims = _encode_claims(claims)
    signed_output = _sign_header_and_claims(encoded_header, encoded_claims, algorithm, key)

    return signed_output


def verify(payload, key, algorithms):
    """Verifies a JWS string's signature.

    Examples:

        >>> payload = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        >>> jws.verify(payload, 'secret', algorithms='HS256')

    Args:
        payload (str): A signed JWS to be verified.
        key (str): A key to attempt to verify the payload with.
        algorithms (str or list): Valid algorithms that should be used to verify the JWS.

    Returns:
        dict: The dict representation of the claims set, assuming the signature is valid.

    Raises:
        Exception: If the signature is invalid in any way.

    """

    pass


def _encode_header(algorithm, additional_headers=None):
    header = {
        "typ": "JWT",
        "alg": algorithm
    }

    if additional_headers:
        header.update(additional_headers)

    json_header = json.dumps(
        header,
        separators=(',', ':'),
    ).encode('utf-8')

    return base64url_encode(json_header)


def _encode_claims(claims):
    json_payload = json.dumps(
        claims,
        separators=(',', ':'),
    ).encode('utf-8')

    return base64url_encode(json_payload)


def _sign_header_and_claims(encoded_header, encoded_claims, algorithm, key):
    signing_input = b'.'.join([encoded_header, encoded_claims])
    try:
        alg_obj = get_algorithm_object(algorithm)
        key = alg_obj.prepare_key(key)
        signature = alg_obj.sign(signing_input, key)
    except:
        raise Exception('Unable to sign header and claims.')

    encoded_signature = base64url_encode(signature)

    return b'.'.join([encoded_header, encoded_claims, encoded_signature])
