
from jose.algorithms import HMACAlgorithm

import unittest


class HMACAlgorithmTestCase(unittest.TestCase):

    def setUp(self):
        self.alg = HMACAlgorithm(HMACAlgorithm.SHA256)

    def test_non_string_key(self):
        self.assertRaises(TypeError, self.alg.prepare_key, object())

    def test_unicode_encode(self):
        key = u'secret'
        prepared_key = self.alg.prepare_key(key)
        self.assertEqual(key, prepared_key)

    def test_RSA_key(self):
        key = "-----BEGIN PUBLIC KEY-----"
        self.assertRaises(Exception, self.alg.prepare_key, key)
