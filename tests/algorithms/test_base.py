
from jose.algorithms import base

import unittest


class BaseAlgorithmTestCase(unittest.TestCase):

    def setUp(self):
        self.alg = base.Algorithm()

    def test_prepare_key_is_interface(self):
        self.assertRaises(NotImplementedError, self.alg.prepare_key, 'secret')

    def test_sign_is_interface(self):
        self.assertRaises(NotImplementedError, self.alg.sign, 'msg', 'secret')

    def test_verify_is_interface(self):
        self.assertRaises(NotImplementedError, self.alg.verify, 'msg', 'secret', 'sig')
