
try:
    from .pycrypto_backend import RSAKey
except ImportError:
    from .cryptography_backend import CryptographyRSAKey as RSAKey
