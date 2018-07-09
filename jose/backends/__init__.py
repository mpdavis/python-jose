
try:
    from jose.backends.pycrypto_backend import RSAKey  # noqa: F401
except ImportError:
    try:
        from jose.backends.cryptography_backend import CryptographyRSAKey as RSAKey  # noqa: F401
    except ImportError:
        from jose.backends.rsa_backend import RSAKey  # noqa: F401

try:
    from jose.backends.cryptography_backend import CryptographyECKey as ECKey  # noqa: F401
except ImportError:
    from jose.backends.ecdsa_backend import ECDSAECKey as ECKey  # noqa: F401
