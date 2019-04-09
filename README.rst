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

    $ pip install python-jose[cryptography]


Cryptographic Backends
----------------------

As of 3.1.0, python-jose implements four different cryptographic backends.
The backend must be selected as an extra when installing python-jose.
If you do not select a backend, the native-python backend will be installed.

Unless otherwise noted, all backends support all operations.

Due to complexities with setuptools, the native-python backend is always installed,
even if you select a different backend on install.
We recommend that you remove unnecessary dependencies in production.

#. cryptography

   * This backend uses `pyca/cryptography`_ for all cryptographic operations.
     This is the recommended backend and is selected over all other backends if any others are present.
   * Installation: ``pip install python-jose[cryptography]``
   * Unused dependencies:

     * ``rsa``
     * ``ecdsa``
     * ``pyasn1``

#. pycryptodome

   * This backend uses `pycryptodome`_ for all cryptographic operations.
   * Installation: ``pip install python-jose[pycryptodome]``
   * Unused dependencies:

     * ``rsa``

#. native-python

   * This backend uses `python-rsa`_ and `python-ecdsa`_ for all cryptographic operations.
     This backend is always installed but any other backend will take precedence if one is installed.
   * Installation: ``pip install python-jose``

   .. note::

       The native-python backend cannot process certificates.

#. pycrypto

   * This backend uses `pycrypto`_ for all cryptographic operations.
   * Installation: ``pip install python-jose[pycrypto]``
   * Unused dependencies:

     * ``rsa``

   .. warning::

       The `pycrypto`_ project has not been maintained since 2013.
       This backend is maintained for legacy compatibility purposes only.
       Do not use this backend unless you cannot use any of the others.

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
.. _pyca/cryptography: http://cryptography.io/
.. _pycryptodome: https://pycryptodome.readthedocs.io/en/latest/
.. _pycrypto: https://www.dlitz.net/software/pycrypto/
.. _python-ecdsa: https://github.com/warner/python-ecdsa
.. _python-rsa: https://stuvel.eu/rsa
