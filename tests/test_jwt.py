
from jose import jwt

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
