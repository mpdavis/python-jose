python-jose
===========

A JOSE implementation in Python

|Build Status| |Coverage Status| |Docs|

Docs are available on ReadTheDocs_.

The JavaScript Object Signing and Encryption (JOSE) technologies - JSON
Web Signature (JWS), JSON Web Encryption (JWE), JSON Web Key (JWK), and
JSON Web Algorithms (JWA) - collectively can be used to encrypt and/or
sign content using a variety of algorithms. While the full set of
permutations is extremely large, and might be daunting to some, it is
expected that most applications will only use a small set of algorithms
to meet their needs.


Installation
------------

::

    $ pip install python-jose


Custom Backends
---------------

As of 3.0.0, python-jose uses the pure-python rsa module by default for RSA signing and verification. If
necessary, other RSA backends are supported. Options include crytography, pycryptodome, and pycrypto.

In order to use a custom backend, install python-jose with the appropriate extra.

It is recommended that a custom backend is used in production, as the pure-python rsa module is slow.

The crytography option is a good default.

::

    $ pip install python-jose[cryptography]
    $ pip install python-jose[pycryptodome]
    $ pip install python-jose[pycrypto]

Due to complexities with setuptools, the ``python-rsa`` and ``python-ecdsa`` libraries are always installed.
If you use one of the custom backends and would like to clean up unneeded dependencies,
you can remove the following dependencies for each backend:

* ``cryptography``

  * ``pip uninstall rsa ecdsa pyasn1``

* ``pycrypto`` or ``pycryptodome``

  * ``pip uninstall rsa``

.. warning::

    Uninstall carefully. Make sure that nothing else in your environment needs these
    libraries before uninstalling them.


Usage
-----

.. code-block:: python

    >>> from jose import jwt
    >>> token = jwt.encode({'key': 'value'}, 'secret', algorithm='HS256')
    u'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkiOiJ2YWx1ZSJ9.FG-8UppwHaFp1LgRYQQeS6EDQF7_6-bMFegNucHjmWg'

    >>> jwt.decode(token, 'secret', algorithms=['HS256'])
    {u'key': u'value'}


Thanks
------

This library was originally based heavily on the work of the folks over at PyJWT_.

.. |Build Status| image:: https://travis-ci.org/mpdavis/python-jose.svg?branch=master
   :target: https://travis-ci.org/mpdavis/python-jose
.. |Coverage Status| image:: http://codecov.io/github/mpdavis/python-jose/coverage.svg?branch=master
   :target: http://codecov.io/github/mpdavis/python-jose?branch=master
.. |Docs| image:: https://readthedocs.org/projects/python-jose/badge/
   :target: https://python-jose.readthedocs.org/en/latest/
.. _ReadTheDocs: https://python-jose.readthedocs.org/en/latest/
.. _PyJWT: https://github.com/jpadilla/pyjwt
