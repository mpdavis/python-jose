
from jose.algorithms import get_algorithm_object

import unittest


class GetAlgorithmTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_get_unsupported(self):
        self.assertRaises(Exception, get_algorithm_object, 'SOMETHING')
