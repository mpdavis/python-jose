JSON Web Key
==============

JSON Web Keys (JWK) are a JSON data structure representing a cryptographic key.

Examples
^^^^^^^^

Verifying token signatures
--------------------------

.. code:: python

    >>> from jose import jwk
    >>> from jose.utils import base64url_decode
    >>>
    >>> token = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
    >>> hmac_key = {
        "kty": "oct",
        "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
        "use": "sig",
        "alg": "HS256",
        "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
    }
    >>>
    >>> key = jwk.construct(hmac_key)
    >>>
    >>> message, encoded_sig = token.rsplit('.', 1)
    >>> decoded_sig = base64url_decode(encoded_sig)
    >>> key.verify(message, decoded_sig)


Note
^^^^
python-jose requires the use of public keys, as opposed to X.509 certificates.  If you have an X.509 certificate that you would like to convert to a public key that python-jose can consume, you can do so with openssl.

.. code:: bash

    > openssl x509 -pubkey -noout < cert.pem
