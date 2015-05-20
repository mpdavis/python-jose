
from jose.jwa import get_algorithm_object

import pytest


@pytest.fixture
def test():
    pass


class TestGetAlgorithm:

    def test_get_algorithm(self):
        with pytest.raises(Exception):
            get_algorithm_object('SOMETHING')
