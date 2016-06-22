
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


Contents
--------

.. toctree::
   :maxdepth: 2

   jws/index
   jwt/index
   jwk/index


APIs
----

.. toctree::
   :maxdepth: 2

   jws/api
   jwt/api
   jwk/api


Principles
----------

This is a JOSE implementation that is fully compatible with Google App Engine
which requires the use of the PyCrypto library.

Thanks
------

This library was originally based heavily on the work of the guys over at PyJWT_.

.. |Build Status| image:: https://travis-ci.org/mpdavis/python-jose.svg?branch=master
   :target: https://travis-ci.org/mpdavis/python-jose
.. |Coverage Status| image:: http://codecov.io/github/mpdavis/python-jose/coverage.svg?branch=master
   :target: http://codecov.io/github/mpdavis/python-jose?branch=master
.. _PyJWT: https://github.com/jpadilla/pyjwt
