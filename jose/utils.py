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
