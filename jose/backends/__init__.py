
try:
    from jose.backends.pycrypto_backend import RSAKey
except ImportError:
    try:
        from jose.backends.cryptography_backend import CryptographyRSAKey as RSAKey
    except ImportError:
        from jose.backends.rsa_backend import RSAKey

try:
    from jose.backends.cryptography_backend import CryptographyECKey as ECKey
except ImportError:
    from jose.backends.ecdsa_backend import ECDSAECKey as ECKey
