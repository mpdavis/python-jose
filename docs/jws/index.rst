JSON Web Signature
==================

JSON Web Signatures (JWS) are used to digitally sign a JSON encoded
object and represent it as a compact URL-safe string.

Supported Algorithms
^^^^^^^^^^^^^^^^^^^^

The following algorithms are currently supported.

+-------------------+---------------------------------------+
| Algorithm Value   | Digital Signature or MAC Algorithm    |
+===================+=======================================+
| HS256             | HMAC using SHA-256 hash algorithm     |
+-------------------+---------------------------------------+
| HS384             | HMAC using SHA-384 hash algorithm     |
+-------------------+---------------------------------------+
| HS512             | HMAC using SHA-512 hash algorithm     |
+-------------------+---------------------------------------+
| RS256             | RSASSA using SHA-256 hash algorithm   |
+-------------------+---------------------------------------+
| RS384             | RSASSA using SHA-384 hash algorithm   |
+-------------------+---------------------------------------+
| RS512             | RSASSA using SHA-512 hash algorithm   |
+-------------------+---------------------------------------+
| ES256             | ECDSA using SHA-256 hash algorithm    |
+-------------------+---------------------------------------+
| ES384             | ECDSA using SHA-384 hash algorithm    |
+-------------------+---------------------------------------+
| ES512             | ECDSA using SHA-512 hash algorithm    |
+-------------------+---------------------------------------+

Examples
^^^^^^^^

Signing tokens
--------------

.. code:: python

    >>> from jose import jws
    >>> signed = jws.sign({'a': 'b'}, 'secret', algorithm='HS256')
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'

Verifying token signatures
--------------------------

.. code:: python

    >>> jws.verify(signed, 'secret', algorithms=['HS256'])
    {'a': 'b'}
