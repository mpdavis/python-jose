JSON Web Encryption
===================

JSON Web Encryption (JWE) are used to encrypt a payload and represent it as a
compact URL-safe string.

Supported Content Encryption Algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following algorithms are currently supported.

+------------------+------------------------------------------------+
| Encryption Value | Encryption Algorithm, Mode, and Auth Tag       |
+==================+================================================+
| A128CBC-HS256    | AES w/128 bit key in CBC mode w/SHA256 HMAC    |
+------------------+------------------------------------------------+
| A192CBC-HS384    | AES w/128 bit key in CBC mode w/SHA256 HMAC    |
+------------------+------------------------------------------------+
| A256CBC-HS512    | AES w/128 bit key in CBC mode w/SHA256 HMAC    |
+------------------+------------------------------------------------+
| A128GCM          | AES w/128 bit key in GCM mode and GCM auth tag |
+------------------+------------------------------------------------+
| A192GCM          | AES w/192 bit key in GCM mode and GCM auth tag |
+------------------+------------------------------------------------+
| A256GCM          | AES w/256 bit key in GCM mode and GCM auth tag |
+------------------+------------------------------------------------+

Supported Key Management Algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following algorithms are currently supported.

+-----------------+------------------------------------------------+
| Algorithm Value | Key Wrap Algorithm                             |
+=================+================================================+
| DIR             | Direct (no key wrap)                           |
+-----------------+------------------------------------------------+
| RSA1-5          | RSAES with PKCS1 v1.5                          |
+-----------------+------------------------------------------------+
| RSA-OAEP        | RSAES OAEP using default parameters            |
+-----------------+------------------------------------------------+
| RSA-OAEP-256    | RSAES OAEP using SHA-256 and MGF1 with SHA-256 |
+-----------------+------------------------------------------------+
| A128KW          | AES Key Wrap with default IV using 128-bit key |
+-----------------+------------------------------------------------+
| A192KW   m      | AES Key Wrap with default IV using 192-bit key |
+-----------------+------------------------------------------------+
| A256KW          | AES Key Wrap with default IV using 256-bit key |
+-----------------+------------------------------------------------+

Examples
^^^^^^^^

Encrypting Payloads
-------------------

.. code:: python

        >>> from jose import jwe
        >>> jwe.encrypt('Hello, World!', 'asecret128bitkey', algorithm='dir', encryption='A128GCM')
        'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..McILMB3dYsNJSuhcDzQshA.OfX9H_mcUpHDeRM4IA.CcnTWqaqxNsjT4eCaUABSg'


Decrypting Payloads
--------------------------

.. code:: python

        >>> from jose import jwe
        >>> jwe.decrypt('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..McILMB3dYsNJSuhcDzQshA.OfX9H_mcUpHDeRM4IA.CcnTWqaqxNsjT4eCaUABSg', 'asecret128bitkey')
        'Hello, World!'
