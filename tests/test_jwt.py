
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


class TestJWT:

    def test_non_default_alg(self, claims, key):
        encoded = jwt.encode(claims, key, algorithm='HS384')
        decoded = jwt.decode(encoded, key, algorithms='HS384')
        assert claims == decoded

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
