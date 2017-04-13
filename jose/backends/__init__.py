
try:
    from jose.backends.pycrypto_backend import RSAKey
except ImportError:
    from jose.backends.cryptography_backend import CryptographyRSAKey as RSAKey

try:
    from jose.backends.ecdsa_backend import ECKey
except ImportError:
    from jose.backends.cryptography_backend import CryptographyECKey as ECKey
