# python-jose

A JOSE implementation in Python

[![Build Status](https://travis-ci.org/mpdavis/python-jose.svg?branch=master)](https://travis-ci.org/mpdavis/python-jose) [![Coverage Status](https://coveralls.io/repos/mpdavis/python-jose/badge.svg)](https://coveralls.io/r/mpdavis/python-jose)

## Principles

This is a JOSE implementation that is meant to be simple to use, both on and off of AppEngine.

## Examples

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
