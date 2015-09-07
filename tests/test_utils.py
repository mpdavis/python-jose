
from datetime import timedelta

from jose import utils


class TestUtils:

    def test_total_seconds(self):
        td = timedelta(seconds=5)

        assert utils.timedelta_total_seconds(td) == 5
