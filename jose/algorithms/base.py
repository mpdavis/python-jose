
from jose.exceptions import JOSEError


class Algorithm(object):
    """
    The interface for an algorithm used to sign and verify tokens.
    """
    def process_sign(self, msg, key):
        """
        Processes a signature for the given algorithm.

        This method should be overriden by the implementing algortihm.
        """
        raise NotImplementedError

    def process_verify(self, msg, key, sig):
        """
        Processes a verification for the given algorithm.

        This method should be overriden by the implementing algorithm.
        """
        raise NotImplementedError

    def process_prepare_key(self, key):
        """
        Processes preparing a key for the given algorithm.

        This method should be overriden by the implementing algorithm.
        """
        raise NotImplementedError

    def prepare_key(self, key):
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().

        This is used to catch any library errors and throw a JOSEError.

        Raises:
            TypeError: If an invalid key is attempted to be used.
        """
        try:
            return self.process_prepare_key(key)
        except Exception, e:
            raise JOSEError(e)

    def sign(self, msg, key):
        """
        Returns a digital signature for the specified message
        using the specified key value.

        This is used to catch any library errors and throw a JOSEError.

        Raises:
            JOSEError: When there is an error creating a signature.
        """
        try:
            return self.process_sign(msg, key)
        except Exception, e:
            raise JOSEError(e)

    def verify(self, msg, key, sig):
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.

        This is used to catch any library errors and throw a JOSEError.

        Raises:
            JOSEError: When there is an error verifiying the signature.
        """
        try:
            return self.process_verify(msg, key, sig)
        except Exception, e:
            raise JOSEError(e)
