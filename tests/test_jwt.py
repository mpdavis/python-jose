
import base64
import json

from jose import jws
from jose import jwt
from jose.exceptions import JWTError

from datetime import datetime
from datetime import timedelta

import pytest


@pytest.fixture
def claims():
    claims = {
        'a': 'b'
    }
    return claims


@pytest.fixture
def key():
    return 'secret'


@pytest.fixture
def headers():
    headers = {
        'kid': 'my-key-id',
    }
    return headers


class TestJWT:

    def test_no_alg(self, claims, key):
        token = jwt.encode(claims, key, algorithm='HS384')
        b64header, b64payload, b64signature = token.split('.')
        header_json = base64.urlsafe_b64decode(b64header.encode('utf-8'))
        header = json.loads(header_json.decode('utf-8'))
        del header['alg']
        bad_header_json_bytes = json.dumps(header).encode('utf-8')
        bad_b64header_bytes = base64.urlsafe_b64encode(bad_header_json_bytes)
        bad_b64header_bytes_short = bad_b64header_bytes.replace(b'=', b'')
        bad_b64header = bad_b64header_bytes.decode('utf-8')
        bad_token = '.'.join([bad_b64header, b64payload, b64signature])
        with pytest.raises(JWTError):
            jwt.decode(
                token=bad_token,
                key=key,
                algorithms=[])

    def test_invalid_claims_json(self):
        old_jws_verify = jws.verify
        try:
            token = u'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'

            def return_invalid_json(token, key, algorithms, verify=True):
                return b'["a", "b"}'

            jws.verify = return_invalid_json

            with pytest.raises(JWTError, match='Invalid payload string: '):
                jwt.decode(token, 'secret', ['HS256'])
        finally:
            jws.verify = old_jws_verify

    def test_invalid_claims(self):
        old_jws_verify = jws.verify
        try:
            token = u'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'

            def return_encoded_array(token, key, algorithms, verify=True):
                return b'["a","b"]'

            jws.verify = return_encoded_array

            with pytest.raises(JWTError, match='Invalid payload string: must be a json object'):
                jwt.decode(token, 'secret', ['HS256'])
        finally:
            jws.verify = old_jws_verify

    def test_non_default_alg(self, claims, key):
        encoded = jwt.encode(claims, key, algorithm='HS384')
        decoded = jwt.decode(encoded, key, algorithms='HS384')
        assert claims == decoded

    def test_non_default_alg_positional_bwcompat(self, claims, key):
        encoded = jwt.encode(claims, key, 'HS384')
        decoded = jwt.decode(encoded, key, 'HS384')
        assert claims == decoded

    def test_no_alg_default_headers(self, claims, key, headers):
        token = jwt.encode(claims, key, algorithm='HS384')
        b64header, b64payload, b64signature = token.split('.')
        bad_token = b64header + '.' + b64payload
        with pytest.raises(JWTError):
            jwt.get_unverified_headers(bad_token)

    def test_non_default_headers(self, claims, key, headers):
        encoded = jwt.encode(claims, key, headers=headers)
        decoded = jwt.decode(encoded, key)
        assert claims == decoded
        all_headers = jwt.get_unverified_headers(encoded)
        for k, v in headers.items():
            assert all_headers[k] == v

    def test_deterministic_headers(self):
        from collections import OrderedDict
        from jose.utils import base64url_decode

        claims = {"a": "b"}
        key = "secret"

        headers1 = OrderedDict((
            ('kid', 'my-key-id'),
            ('another_key', 'another_value'),
        ))
        encoded1 = jwt.encode(claims, key, algorithm='HS256', headers=headers1)
        encoded_headers1 = encoded1.split('.', 1)[0]

        headers2 = OrderedDict((
            ('another_key', 'another_value'),
            ('kid', 'my-key-id'),
        ))
        encoded2 = jwt.encode(claims, key, algorithm='HS256', headers=headers2)
        encoded_headers2 = encoded2.split('.', 1)[0]

        assert encoded_headers1 == encoded_headers2

        # manually decode header to compare it to known good
        decoded_headers1 = base64url_decode(encoded_headers1.encode('utf-8'))
        assert decoded_headers1 == b"""{"alg":"HS256","another_key":"another_value","kid":"my-key-id","typ":"JWT"}"""

    def test_encode(self, claims, key):

        expected = (
            (
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'
                '.eyJhIjoiYiJ9'
                '.xNtk2S0CNbCBZX_f67pFgGRugaP1xi2ICfet3nwOSxw'
            ),
            (
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                '.eyJhIjoiYiJ9'
                '.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
            )
        )

        encoded = jwt.encode(claims, key)

        assert encoded in expected

    def test_decode(self, claims, key):

        token = (
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            '.eyJhIjoiYiJ9'
            '.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
        )

        decoded = jwt.decode(token, key)

        assert decoded == claims

    def test_leeway_is_int(self):
        pass

    def test_leeway_is_timedelta(self, claims, key):

        nbf = datetime.utcnow() + timedelta(seconds=5)
        leeway = timedelta(seconds=10)

        claims = {
            'nbf': nbf,
        }

        options = {
            'leeway': leeway
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, options=options)

    def test_iat_not_int(self, key):

        claims = {
            'iat': 'test'
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_nbf_not_int(self, key):

        claims = {
            'nbf': 'test'
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_nbf_datetime(self, key):

        nbf = datetime.utcnow() - timedelta(seconds=5)

        claims = {
            'nbf': nbf
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_nbf_with_leeway(self, key):

        nbf = datetime.utcnow() + timedelta(seconds=5)

        claims = {
            'nbf': nbf,
        }

        options = {
            'leeway': 10
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, options=options)

    def test_nbf_in_future(self, key):

        nbf = datetime.utcnow() + timedelta(seconds=5)

        claims = {
            'nbf': nbf
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_nbf_skip(self, key):

        nbf = datetime.utcnow() + timedelta(seconds=5)

        claims = {
            'nbf': nbf
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

        options = {
            'verify_nbf': False
        }

        jwt.decode(token, key, options=options)

    def test_exp_not_int(self, key):

        claims = {
            'exp': 'test'
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_exp_datetime(self, key):

        exp = datetime.utcnow() + timedelta(seconds=5)

        claims = {
            'exp': exp
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_exp_with_leeway(self, key):

        exp = datetime.utcnow() - timedelta(seconds=5)

        claims = {
            'exp': exp,
        }

        options = {
            'leeway': 10
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, options=options)

    def test_exp_in_past(self, key):

        exp = datetime.utcnow() - timedelta(seconds=5)

        claims = {
            'exp': exp
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_exp_skip(self, key):

        exp = datetime.utcnow() - timedelta(seconds=5)

        claims = {
            'exp': exp
        }

        token = jwt.encode(claims, key)

        with pytest.raises(JWTError):
            jwt.decode(token, key)

        options = {
            'verify_exp': False
        }

        jwt.decode(token, key, options=options)

    def test_aud_string(self, key):

        aud = 'audience'

        claims = {
            'aud': aud
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_list(self, key):

        aud = 'audience'

        claims = {
            'aud': [aud]
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_list_multiple(self, key):

        aud = 'audience'

        claims = {
            'aud': [aud, 'another']
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_list_is_strings(self, key):

        aud = 'audience'

        claims = {
            'aud': [aud, 1]
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, audience=aud)

    def test_aud_case_sensitive(self, key):

        aud = 'audience'

        claims = {
            'aud': [aud]
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, audience='AUDIENCE')

    def test_aud_empty_claim(self, claims, key):

        aud = 'audience'

        token = jwt.encode(claims, key)
        jwt.decode(token, key, audience=aud)

    def test_aud_not_string_or_list(self, key):

        aud = 1

        claims = {
            'aud': aud
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_aud_given_number(self, key):

        aud = 'audience'

        claims = {
            'aud': aud
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, audience=1)

    def test_iss_string(self, key):

        iss = 'issuer'

        claims = {
            'iss': iss
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, issuer=iss)

    def test_iss_list(self, key):

        iss = 'issuer'

        claims = {
            'iss': iss
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, issuer=['https://issuer', 'issuer'])

    def test_iss_tuple(self, key):

        iss = 'issuer'

        claims = {
            'iss': iss
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, issuer=('https://issuer', 'issuer'))

    def test_iss_invalid(self, key):

        iss = 'issuer'

        claims = {
            'iss': iss
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, issuer='another')

    def test_sub_string(self, key):

        sub = 'subject'

        claims = {
            'sub': sub
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_sub_invalid(self, key):

        sub = 1

        claims = {
            'sub': sub
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_sub_correct(self, key):

        sub = 'subject'

        claims = {
            'sub': sub
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key, subject=sub)

    def test_sub_incorrect(self, key):

        sub = 'subject'

        claims = {
            'sub': sub
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, subject='another')

    def test_jti_string(self, key):

        jti = 'JWT ID'

        claims = {
            'jti': jti
        }

        token = jwt.encode(claims, key)
        jwt.decode(token, key)

    def test_jti_invalid(self, key):

        jti = 1

        claims = {
            'jti': jti
        }

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_at_hash(self, claims, key):
        access_token = '<ACCESS_TOKEN>'
        token = jwt.encode(claims, key, access_token=access_token)
        payload = jwt.decode(token, key, access_token=access_token)
        assert 'at_hash' in payload

    def test_at_hash_invalid(self, claims, key):
        token = jwt.encode(claims, key, access_token='<ACCESS_TOKEN>')
        with pytest.raises(JWTError):
            jwt.decode(token, key, access_token='<OTHER_TOKEN>')

    def test_at_hash_missing_access_token(self, claims, key):
        token = jwt.encode(claims, key, access_token='<ACCESS_TOKEN>')
        with pytest.raises(JWTError):
            jwt.decode(token, key)

    def test_at_hash_missing_claim(self, claims, key):
        token = jwt.encode(claims, key)
        payload = jwt.decode(token, key, access_token='<ACCESS_TOKEN>')
        assert 'at_hash' not in payload

    def test_at_hash_unable_to_calculate(self, claims, key):
        token = jwt.encode(claims, key, access_token='<ACCESS_TOKEN>')
        with pytest.raises(JWTError):
            jwt.decode(token, key, access_token='\xe2')

    def test_bad_claims(self):
        bad_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.iOJ5SiNfaNO_pa2J4Umtb3b3zmk5C18-mhTCVNsjnck'
        with pytest.raises(JWTError):
            jwt.get_unverified_claims(bad_token)

    def test_unverified_claims_string(self):
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW52YWxpZCBjbGFpbQ.iOJ5SiNfaNO_pa2J4Umtb3b3zmk5C18-mhTCVNsjnck'
        with pytest.raises(JWTError):
            jwt.get_unverified_claims(token)

    def test_unverified_claims_list(self):
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.WyJpbnZhbGlkIiwgImNsYWltcyJd.nZvw_Rt1FfUPb5OiVbrSYZGtWSE5c-gdJ6nQnTTBkYo'
        with pytest.raises(JWTError):
            jwt.get_unverified_claims(token)

    def test_unverified_claims_object(self, claims, key):
        token = jwt.encode(claims, key)
        assert jwt.get_unverified_claims(token) == claims

    @pytest.mark.parametrize(
        "claim,value", [
            ("aud", "aud"),
            ("ait", "ait"),
            ("exp", datetime.utcnow() + timedelta(seconds=3600)),
            ("nbf", datetime.utcnow() - timedelta(seconds=5)),
            ("iss", "iss"),
            ("sub", "sub"),
            ("jti", "jti"),
        ]
    )
    def test_require(self, claims, key, claim, value):
        options = {"require_" + claim: True, "verify_" + claim: False}

        token = jwt.encode(claims, key)
        with pytest.raises(JWTError):
            jwt.decode(token, key, options=options, audience=str(value))

        new_claims = dict(claims)
        new_claims[claim] = value
        token = jwt.encode(new_claims, key)
        jwt.decode(token, key, options=options, audience=str(value))
