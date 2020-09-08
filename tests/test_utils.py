
from datetime import timedelta

import pytest

from jose import utils


b64_to_bstr = [
    ('', b''),
    ('YQ', b'a'),
    ('YXM', b'as'),
    ('YXNk', b'asd'),
    ('YXNkZg', b'asdf'),
    ('YXNkZnE', b'asdfq'),
    ('YXNkZnF3', b'asdfqw'),
    ('YXNkZnF3ZQ', b'asdfqwe'),
    ('YXNkZnF3ZXI', b'asdfqwer'),
    ('YXNkZnF3ZXJ0', b'asdfqwert'),
    ('YXNkZnF3ZXJ0eQ', b'asdfqwerty'),
]

b64b_to_bstr = [
    (b64.encode('ascii'), bstr)
    for (b64, bstr) in b64_to_bstr
]


class TestUtils:

    def test_total_seconds(self):
        td = timedelta(seconds=5)

        assert utils.timedelta_total_seconds(td) == 5

    @pytest.mark.parametrize("longdata, kwargs, b64", [
        (0xDEADBEEF, {}, b'3q2-7w'),
        (0xCAFED00D, {'size': 10}, b'AAAAAAAAyv7QDQ'),
    ])
    def test_long_to_base64(self, longdata, kwargs, b64):
        assert utils.long_to_base64(longdata, **kwargs) == b64

    @pytest.mark.parametrize("b64b, bstr", b64b_to_bstr)
    def test_base64url_encode_bytes(self, b64b, bstr):
        assert b64b == utils.base64url_encode(bstr)

    @pytest.mark.parametrize("b64b, bstr", b64b_to_bstr)
    def test_base64url_decode_bytes(self, b64b, bstr):
        assert utils.base64url_decode(b64b) == bstr

    @pytest.mark.parametrize("b64str, bstr", b64_to_bstr)
    def test_base64url_decode_string(self, b64str, bstr):
        assert utils.base64url_decode(b64str) == bstr
