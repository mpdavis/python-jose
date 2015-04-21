
from jose import jwt
from jose.constants import ALGORITHMS

import unittest


class JWTTestCase(unittest.TestCase):

    def setUp(self):
        self.claims = {
            'test': 'input'
        }
        self.key = 'secret'

    def test_encode(self):
        jwt.encode(self.claims, self.key)

    def test_decode(self):
        jwt.decode('test', self.key)
