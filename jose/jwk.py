
import six

from Crypto.PublicKey import RSA

from jose.exceptions import JWKError
from jose.utils import base64_to_long
from jose.utils import base64url_to_long
from jose.utils import long_to_base64
from jose.utils import utf_decode

PREFIX = "-----BEGIN CERTIFICATE-----"
POSTFIX = "-----END CERTIFICATE-----"


class Key(object):
    """
    Represents a JWK object
    """

    public_keys = ["kty", "kid", "alg", "use", "x5t", "x5u", "x5c"]

    def __init__(self, kty='', kid='', alg='', use='', x5t='', x5u='', x5c=None, key=None):

        self.key = key
        self.x5t = x5t
        self.x5u = x5u
        self.x5c = x5c or []

        self.kty = utf_decode(kty)
        self.kid = utf_decode(kid)
        self.alg = utf_decode(alg)
        self.use = utf_decode(use)

    def serialize(self):
        """Map a Key object to a JWK representation."""
        pass

    def deserialize(self):
        """Map a JWK to a Key representation."""
        pass

    def to_dict(self):
        _dict = self.serialize()

        res = {}
        for key in self.public_keys:
            try:
                res[key] = _dict[key]
            except (KeyError, AttributeError):
                pass
        return res

    def common(self):
        res = {"kty": self.kty}
        if self.use:
            res["use"] = self.use
        if self.kid:
            res["kid"] = self.kid
        if self.alg:
            res["alg"] = self.alg
        return res

    def __str__(self):
        return str(self.to_dict())

    def verify(self):
        """
        Verify that the information gathered from the serialized
        representation is of the right types.

        This is supposed to be run before the info is deserialized.
        """
        for param in self.longs:
            item = getattr(self, param)
            if not item or isinstance(item, six.integer_types):
                continue

            if isinstance(item, bytes):
                item = str(item)
                setattr(self, param, item)

            try:
                base64url_to_long(item)
            except Exception:
                return False
            else:
                if [e for e in ['+', '/', '='] if e in item]:
                    return False

        if self.kid:
            try:
                assert isinstance(self.kid, six.string_types)
            except AssertionError:
                raise JWKError("kid of wrong value type")
        return True


def deser(val):
    if isinstance(val, str):
        _val = val.encode("utf-8")
    else:
        _val = val

    return base64_to_long(_val)


def import_rsa_key(key):
    """
    Extract an RSA key from a PEM-encoded certificate
    :param key: RSA key encoded in standard form
    :return: RSA key instance
    """
    return RSA.importKey(key)


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    pem = open(filename, 'r').read()
    return import_rsa_key(pem)


class RSAKey(Key):
    """
    JSON Web key representation of a RSA key
    """
    members = Key.members
    members.extend(["n", "e", "d", "p", "q"])
    longs = ["n", "e", "d", "p", "q"]
    public_members = Key.public_members
    public_members.extend(["n", "e"])

    def __init__(self, kty="RSA", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u="", n="", e="", d="", p="", q="",
                 dp="", dq="", di="", qi=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.di = di
        self.qi = qi

        if not self.key and self.n and self.e:
            self.deserialize()
        elif self.key and not (self.n and self.e):
            self._split()

    def deserialize(self):
        if self.n and self.e:
            try:
                self.e = long(deser(self.e))
                self.n = deser(self.n)
                if self.d:
                    self.d = deser(self.d)
                    self.key = RSA.construct((self.n, self.e, self.d))
                else:
                    self.key = RSA.construct((self.n, self.e))
            except ValueError as err:
                raise JWKError("%s" % err)
        elif self.x5c:
            if self.x5t:  # verify the cert
                pass

            cert = "\n".join([PREFIX, str(self.x5c[0]), POSTFIX])
            self.key = import_rsa_key(cert)
            self._split()
            if len(self.x5c) > 1:  # verify chain
                pass
        else:
            raise JWKError()

    def serialize(self, private=False):
        if not self.key:
            raise JWKError()

        res = self.common()
        res.update({
            "n": long_to_base64(self.n),
            "e": long_to_base64(self.e)
        })
        if private:
            res["d"] = long_to_base64(self.d)
        return res

    def _split(self):
        self.n = self.key.n
        self.e = self.key.e
        try:
            self.d = self.key.d
        except AttributeError:
            pass

    def load(self, filename):
        """
        Load the key from a file.
        :param filename: File name
        """
        self.key = rsa_load(filename)
        self._split()
        return self

    def load_key(self, key):
        """
        Use this RSA key
        :param key: An RSA key instance
        """
        self.key = key
        self._split()
        return self

    def encryption_key(self, **kwargs):
        """
        Make sure there is a key instance present that can be used for
        encrypting/signing.
        """
        if not self.key:
            self.deserialize()

        return self.key
