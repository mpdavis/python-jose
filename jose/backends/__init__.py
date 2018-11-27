
try:
    from jose.backends.cryptography_backend import CryptographyRSAKey as RSAKey  # noqa: F401
except ImportError:
    try:
        from jose.backends.pycrypto_backend import RSAKey  # noqa: F401
    except ImportError:
        from jose.backends.rsa_backend import RSAKey  # noqa: F401

try:
    from jose.backends.cryptography_backend import CryptographyECKey as ECKey  # noqa: F401
except ImportError:
    from jose.backends.ecdsa_backend import ECDSAECKey as ECKey  # noqa: F401

try:
    from jose.backends.nacl_backend import Ed25519Key  # noqa: F401
except ImportError:
    pass
else:
    # Since PyNaCl is an optional dependency, we do not add EdDSA to the set
    # of supported algorithms in the jose.constants module.
    # As a result, when we successfully import Ed25519Key, we need to manually
    # register that algorithm, but we cannot do it in the jose.constants module
    # because that would create a circular import. Instead, we do it here.
    # TODO: Refactor to use __init_subclass__ hook on jose.backends.base.Key
    import jose.constants as j_c
    j_c.ALGORITHMS.SUPPORTED = j_c.ALGORITHMS.SUPPORTED.union(j_c.ALGORITHMS.ED)
    j_c.ALGORITHMS.ALL = j_c.ALGORITHMS.SUPPORTED.union([j_c.ALGORITHMS.NONE])
