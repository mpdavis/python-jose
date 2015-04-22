
from datetime import timedelta

import unittest

from jose import utils

class UtilsTestCase(unittest.TestCase):

    def test_total_seconds(self):
        td = timedelta(seconds=5)

        self.assertEqual(utils.timedelta_total_seconds(td), 5)

    