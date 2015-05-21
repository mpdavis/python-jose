import base64
import six
import struct


def base64url_decode(input):
    """Helper method to base64url_decode a string.

    Args:
        input (str): A base64url_encoded string to decode.

    """
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    """Helper method to base64url_encode a string.

    Args:
        input (str): A base64url_encoded string to encode.

    """
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def timedelta_total_seconds(delta):
    """Helper method to determine the total number of seconds
    from a timedelta.

    Args:
        delta (timedelta): A timedelta to convert to seconds.
    """
    return delta.days * 24 * 60 * 60 + delta.seconds


def constant_time_compare(a, b):
    """Helper method to compare two strings in constant time.

    Strings need to be compared in constant time when worried
    about timing attacks.

    Args:
        a (str): The first string to compare.
        b (str): The second string to compare.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def utf_decode(string):
    """Method to UTF decode a string, if necessary.

    Args:
        string (str): A string to UTF decode, if necessary.
    """
    r_string = string
    if not isinstance(string, six.string_types):
        r_string = r_string.decode('utf8')

    return r_string


def int_arr_to_long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def long_to_base64(n):
    bys = int_arr_to_long(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s


def base64url_to_long(data):
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    # verify that it's base64url encoded and not just base64
    # that is no '+' and '/' characters and not trailing "="s.
    if [e for e in [b'+', b'/', b'='] if e in data]:
        raise ValueError("Not base64url encoded")
    return int_arr_to_long(struct.unpack('%sB' % len(_d), _d))


def base64_to_long(data):
    # if isinstance(data, str):
    #     data = bytes(data)
    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return int_arr_to_long(struct.unpack('%sB' % len(_d), _d))
