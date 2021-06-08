try:
    from jose.backends.cryptography_backend import get_random_bytes  # noqa: F401
except ImportError:
    try:
        from jose.backends.pycrypto_backend import get_random_bytes  # type: ignore  # noqa: F401
    except ImportError:
        from jose.backends.native import get_random_bytes  # noqa: F401

try:
    from jose.backends.cryptography_backend import CryptographyRSAKey as RSAKey  # noqa: F401
except ImportError:
    try:
        from jose.backends.rsa_backend import RSAKey  # type: ignore  # noqa: F401
    except ImportError:
        RSAKey = None  # type: ignore

try:
    from jose.backends.cryptography_backend import CryptographyECKey as ECKey  # noqa: F401
except ImportError:
    from jose.backends.ecdsa_backend import ECDSAECKey as ECKey  # type: ignore  # noqa: F401

try:
    from jose.backends.cryptography_backend import CryptographyAESKey as AESKey  # noqa: F401
except ImportError:
    AESKey = None  # type: ignore

try:
    from jose.backends.cryptography_backend import CryptographyHMACKey as HMACKey  # noqa: F401
except ImportError:
    from jose.backends.native import HMACKey  # type: ignore  # noqa: F401

from .base import DIRKey  # noqa: F401
