import os


def get_random_bytes(num_bytes):
    return bytes(os.urandom(num_bytes))
