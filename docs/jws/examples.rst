JSON Web Signature
==================

JSON Web Signatures (JWS) are used to digitally sign a JSON encoded
object and represent it as a compact URL-safe string.

Signing tokens
^^^^^^^^^^^^^^

.. code:: python

    >>> from jose import jws
    >>> signed = jws.sign({'a': 'b'}, 'secret', algorithm='HS256')
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'

Verifying token signatures
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: python

    >>> jws.verify(signed, 'secret', algorithms=['HS256'])
    {'a': 'b'}