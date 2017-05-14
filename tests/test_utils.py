
from datetime import timedelta

from jose import utils


class TestUtils:

    def test_total_seconds(self):
        td = timedelta(seconds=5)

        assert utils.timedelta_total_seconds(td) == 5

    def test_long_to_base64(self):
        assert utils.long_to_base64(0xDEADBEEF) == b'3q2-7w'
        assert utils.long_to_base64(0xCAFED00D, size=10) == b'AAAAAAAAyv7QDQ'
