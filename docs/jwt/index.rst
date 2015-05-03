JSON Web Token
==============

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