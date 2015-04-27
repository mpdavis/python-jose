python-jose
===========

A JOSE implementation in Python

|Build Status| |Coverage Status|

The JavaScript Object Signing and Encryption (JOSE) technologies - JSON
Web Signature (JWS), JSON Web Encryption (JWE), JSON Web Key (JWK), and
JSON Web Algorithms (JWA) - collectively can be used to encrypt and/or
sign content using a variety of algorithms. While the full set of
permutations is extremely large, and might be daunting to some, it is
expected that most applications will only use a small set of algorithms
to meet their needs.

Principles
----------

This is a JOSE implementation that is meant to be simple to use, both on
and off of AppEngine.

Examples
--------

JSON Web Signature
~~~~~~~~~~~~~~~~~~

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

JSON Web Token
~~~~~~~~~~~~~~

JSON Web Tokens (JWT) are a JWS with a set of reserved claims to be used
in a standardized manner.

JWT Reserved Claims
^^^^^^^^^^^^^^^^^^^

+---------+--------------+--------------------+-----------------------------------------------+
| Claim   | Name         | Format             | Usage                                         |
+=========+==============+====================+===============================================+
| 'exp'   | Expiration   | int                | The time after which the token is invalid.    |
+---------+--------------+--------------------+-----------------------------------------------+
| 'nbf'   | Not Before   | int                | The time before which the token is invalid.   |
+---------+--------------+--------------------+-----------------------------------------------+
| 'iss'   | Issuer       | str                | The principal that issued the JWT.            |
+---------+--------------+--------------------+-----------------------------------------------+
| 'aud'   | Audience     | str or list(str)   | The recipient that the JWT is intended for.   |
+---------+--------------+--------------------+-----------------------------------------------+
| 'iat'   | Issued At    | int                | The time at which the JWT was issued.         |
+---------+--------------+--------------------+-----------------------------------------------+

Algorithms
----------

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

Thanks
------

This library is based heavily on the work of the guys over at
`PyJWT <https://github.com/jpadilla/pyjwt>`__.

.. |Build Status| image:: https://travis-ci.org/mpdavis/python-jose.svg?branch=master
   :target: https://travis-ci.org/mpdavis/python-jose
.. |Coverage Status| image:: https://coveralls.io/repos/mpdavis/python-jose/badge.svg
   :target: https://coveralls.io/r/mpdavis/python-jose
