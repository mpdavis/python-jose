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
