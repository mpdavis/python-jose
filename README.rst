python-jose
===========

A JOSE implementation in Python

|Build Status| |Coverage Status| |Docs|

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


Thanks
------

This library is based heavily on the work of the guys over at
`PyJWT <https://github.com/jpadilla/pyjwt>`__.

.. |Build Status| image:: https://travis-ci.org/mpdavis/python-jose.svg?branch=master
   :target: https://travis-ci.org/mpdavis/python-jose
.. |Coverage Status| image:: https://coveralls.io/repos/mpdavis/python-jose/badge.svg
   :target: https://coveralls.io/r/mpdavis/python-jose
.. |Docs| image:: https://readthedocs.org/projects/python-jose/badge/
   :target: https://python-jose.readthedocs.org/en/latest/
