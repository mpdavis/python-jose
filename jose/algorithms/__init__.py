
from jose.constants import ALGORITHMS

from .HMAC import HMACAlgorithm


def get_algorithm_object(algorithm):
    """
    Returns an algorithm object for the given algorithm.
    """
    if algorithm not in ALGORITHMS.SUPPORTED:
        raise Exception('Algorithm not supported: %s' % algorithm)

    if algorithm == ALGORITHMS.HS256:
        return HMACAlgorithm(HMACAlgorithm.SHA256)

    if algorithm == ALGORITHMS.HS384:
        return HMACAlgorithm(HMACAlgorithm.SHA384)

    if algorithm == ALGORITHMS.HS512:
        return HMACAlgorithm(HMACAlgorithm.SHA512)

    raise Exception('No algorithm found for %s.' % algorithm)
