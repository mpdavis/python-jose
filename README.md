# python-jose

A JOSE implementation in Python

[![Build Status](https://travis-ci.org/mpdavis/python-jose.svg?branch=master)](https://travis-ci.org/mpdavis/python-jose) [![Coverage Status](https://coveralls.io/repos/mpdavis/python-jose/badge.svg)](https://coveralls.io/r/mpdavis/python-jose)

The JavaScript Object Signing and Encryption (JOSE) technologies -
JSON Web Signature (JWS), JSON Web Encryption (JWE), JSON Web Key
(JWK), and JSON Web Algorithms (JWA) - collectively can be used to
encrypt and/or sign content using a variety of algorithms.  While the
full set of permutations is extremely large, and might be daunting to
some, it is expected that most applications will only use a small set
of algorithms to meet their needs.

## Principles

This is a JOSE implementation that is meant to be simple to use, both on and off of AppEngine.

## Examples

### JSON Web Signature

JSON Web Signatures (JWS) are used to digitally sign a JSON encoded object and represent it as a compact URL-safe string.

#### Signing tokens

```python
>>> from jose import jws
>>> signed = jws.sign({'a': 'b'}, 'secret', algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8'
```

#### Verifying token signatures

```python
>>> jws.verify(signed, 'secret', algorithms=['HS256'])
{'a': 'b'}
```

### JSON Web Token

JSON Web Tokens are a JWS with a set of reserved claims to be used in a standardized manner.


## Algorithms

The following algorithms are currently supported.

Algorithm Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm

## Thanks

This library is based heavily on the work of the guys over at [PyJWT](https://github.com/jpadilla/pyjwt).
