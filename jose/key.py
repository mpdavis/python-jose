import six
import sys
import base64
import struct

# Why this file is necessary: dependencies need to 
# go in one direction to avoid recursive imports. 
# the cryptography and pycrypto both need to depend
# on this file, but this file cannot depend on them.
# Additionally, jwk cannot depend on either cryptography
# or pycrypto, because they may not be available.


class Key(object):
    """
    A simple interface for implementing JWK keys.
    """

    def __init__(self, key, algorithm):
        pass

    def sign(self, msg):
        raise NotImplementedError()

    def verify(self, msg, sig):
        raise NotImplementedError()


# Deal with integer compatibilities between Python 2 and 3.
# Using `from builtins import int` is not supported on AppEngine.
if sys.version_info > (3, ):
    long = int

ALGORITHMS = {}


def register_algorithm_objects(objects):
    global ALGORITHMS

    ALGORITHMS.update(objects)


def get_algorithm_object(algorithm):

    global ALGORITHMS

    return ALGORITHMS.get(algorithm, None)


def int_arr_to_long(arr):
    return long(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return int_arr_to_long(struct.unpack('%sB' % len(_d), _d))
