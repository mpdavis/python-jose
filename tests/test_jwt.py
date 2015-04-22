
from jose import jwt

from datetime import datetime
from datetime import timedelta
import unittest


class JWTTestCase(unittest.TestCase):

    def setUp(self):
        self.claims = {
            'a': 'b'
        }
        self.key = 'secret'
        self.token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'

    def test_encode(self):
        encoded = jwt.encode(self.claims, self.key)
        self.assertEqual(encoded, self.token)

    def test_decode(self):
        decoded = jwt.decode(self.token, self.key)
        self.assertEqual(decoded, self.claims)

    def test_iat_not_int(self):
        self.claims = {
            'a': 'b',
            'iat': 'test'
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, ['HS256'])

    def test_iat_skip_validation(self):
        self.claims = {
            'a': 'b',
            'iat': datetime.utcnow() + timedelta(days=1)
        }
        token = jwt.encode(self.claims, self.key)
        jwt.decode(token, self.key, ['HS256'], options={'verify_iat': False})

    def test_nbf_not_int(self):
        self.claims = {
            'a': 'b',
            'nbf': 'test'
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, ['HS256'])

    def test_nbf_in_future(self):
        self.claims = {
            'a': 'b',
            'nbf': datetime.utcnow() + timedelta(days=1)
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, ['HS256'])

    def test_nbf_skip_validation(self):
        self.claims = {
            'a': 'b',
            'nbf': datetime.utcnow() + timedelta(days=1)
        }
        token = jwt.encode(self.claims, self.key)
        jwt.decode(token, self.key, ['HS256'], options={'verify_nbf': False})

    def test_exp_not_int(self):
        self.claims = {
            'a': 'b',
            'exp': 'test'
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, ['HS256'])

    def test_exp_in_past(self):
        self.claims = {
            'a': 'b',
            'exp': datetime.utcnow() - timedelta(seconds=1)
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, ['HS256'])

    def test_exp_in_past_within_leeway(self):
        self.claims = {
            'a': 'b',
            'exp': datetime.utcnow() - timedelta(seconds=1)
        }
        token = jwt.encode(self.claims, self.key)
        jwt.decode(token, self.key, algorithms=['HS256'], options={'leeway': 2})

    def test_exp_skip_validation(self):
        self.claims = {
            'a': 'b',
            'exp': datetime.utcnow() - timedelta(seconds=1)
        }
        token = jwt.encode(self.claims, self.key)
        jwt.decode(token, self.key, algorithms=['HS256'], options={'verify_exp': False})

    def test_aud_is_string(self):
        self.claims = {
            'a': 'b',
            'aud': 'audience'
        }
        token = jwt.encode(self.claims, self.key)
        jwt.decode(token, self.key, audience='audience', algorithms=['HS256'])

    def test_aud_is_dict(self):
        self.claims = {
            'a': 'b',
            'aud': {'a': 'b'}
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, ['HS256'])

    # TODO: This shouldn't except
    def test_aud_in_claims(self):
        self.claims = {
            'a': 'b',
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, audience='audience', algorithms=['HS256'])

    def test_aud_invalid(self):
        self.claims = {
            'a': 'b',
            'aud': 'audience',
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, audience='another', algorithms=['HS256'])

    def test_issuer_invalid(self):
        self.claims = {
            'a': 'b',
            'iss': 'issuer',
        }
        token = jwt.encode(self.claims, self.key)
        self.assertRaises(Exception, jwt.decode, token, self.key, issuer='another', algorithms=['HS256'])











