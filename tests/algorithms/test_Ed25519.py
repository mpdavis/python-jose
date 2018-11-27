
import base64

from jose.backends.nacl_backend import Ed25519Key
from jose.constants import ALGORITHMS, USAGES
from jose.exceptions import JWKError

from nacl.encoding import URLSafeBase64Encoder
from nacl.signing import SigningKey, VerifyKey

import pytest


SIGNING_KEY = "npAVhmIfq2byvIzcmgS5cguKCv2Nw8Seqa1Fku00LoE="
nacl_signing_key = SigningKey(SIGNING_KEY.encode('utf-8'), encoder=URLSafeBase64Encoder)
nacl_verify_key = nacl_signing_key.verify_key
VERIFY_KEY = base64.urlsafe_b64encode(bytes(nacl_verify_key))


class TestEd25519Algorithm:

    @pytest.mark.parametrize("alg", ALGORITHMS.ED)
    @pytest.mark.parametrize("use", USAGES.ALL)
    def test_Ed25519_key(self, alg, use):
        assert Ed25519Key(SIGNING_KEY, algorithm=alg, use=use)._prepared_key
        assert Ed25519Key(SIGNING_KEY.encode('utf-8'), algorithm=alg, use=use)._prepared_key
        # With Ed25519, there is no difference between seeds for private and public keys, and ALL
        # 256-bit values are valid seeds, so since we have already tested with private key seeds,
        # we do not need to also test for public key seeds

    @pytest.mark.parametrize("alg", ALGORITHMS.ED)
    def test_Ed25519_signing_key(self, alg):
        assert Ed25519Key(nacl_signing_key, algorithm=alg)._prepared_key
        assert not Ed25519Key(nacl_signing_key, algorithm=alg).is_public()

    @pytest.mark.parametrize("alg", ALGORITHMS.ED)
    def test_Ed25519_verify_key(self, alg):
        assert Ed25519Key(nacl_verify_key, algorithm=alg)._prepared_key
        assert Ed25519Key(nacl_verify_key, algorithm=alg).is_public()

    def test_Ed25519_key_unknown_object(self):
        with pytest.raises(JWKError):
            Ed25519Key(object(), algorithm=ALGORITHMS.EdDSA)

    @pytest.mark.parametrize("use", USAGES.ALL)
    def test_Ed25519_key_bad_alg(self, use):
        with pytest.raises(JWKError):
            Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.ES256, use=use)

    @pytest.mark.parametrize("alg", ALGORITHMS.ED)
    def test_Ed25519_key_bad_use(self, alg):
        with pytest.raises(JWKError):
            Ed25519Key(SIGNING_KEY, algorithm=alg)

        with pytest.raises(JWKError):
            Ed25519Key(SIGNING_KEY, algorithm=alg, use=None)

        with pytest.raises(JWKError):
            Ed25519Key(SIGNING_KEY, algorithm=alg, use='bad_usage')

    def test_get_verify_key(self):
        signing_key = Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PRIVATE)

        assert not signing_key.is_public()

        verify_key = signing_key.public_key()  # public_key is part of the Key API
        verify_key2 = verify_key.public_key()

        assert verify_key.is_public()
        assert verify_key is verify_key2

    def test_to_pem(self):
        signing_key = Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PRIVATE)

        with pytest.raises(NotImplementedError):
            signing_key.to_pem()

    def test_verify_key_to_pem(self):
        signing_key = Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PRIVATE)
        verify_key = signing_key.public_key()

        with pytest.raises(NotImplementedError):
            verify_key.to_pem()

    def assert_parameters(self, as_dict, private):
        assert isinstance(as_dict, dict)

        # Public parameters should always be there
        assert 'x' in as_dict

        if private:
            # Private parameters as well
            assert 'd' in as_dict
        else:
            # Private parameters should be absent
            assert 'd' not in as_dict

    def assert_roundtrip(self, key, use):
        assert Ed25519Key(key.to_dict(), ALGORITHMS.EdDSA, use=use).to_dict() == key.to_dict()

    def test_signing_key_to_dict(self):
        key = Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PRIVATE)

        self.assert_parameters(key.to_dict(), private=True)
        self.assert_roundtrip(key, use=USAGES.PRIVATE)

    def test_verify_key_to_dict(self):
        key = Ed25519Key(VERIFY_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PUBLIC)

        self.assert_parameters(key.to_dict(), private=False)
        self.assert_roundtrip(key, use=USAGES.PUBLIC)

    def test_verify_key_from_bad_dict(self):
        key = Ed25519Key(VERIFY_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PUBLIC)
        key_dict = key.to_dict()

        bad_key_dict = key_dict.copy()
        bad_key_dict['kty'] = "SOMETHING_ELSE"

        with pytest.raises(JWKError):
            Ed25519Key(bad_key_dict, algorithm=ALGORITHMS.EdDSA)

        bad_key_dict = key_dict.copy()
        bad_key_dict['crv'] = "SOMETHING_ELSE"

        with pytest.raises(JWKError):
            Ed25519Key(bad_key_dict, algorithm=ALGORITHMS.EdDSA)

    def test_signing_bytes_parity(self):
        signing_key = Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PRIVATE)
        verify_key = signing_key.public_key()

        msg = b'test'
        smsg = signing_key.sign(msg)  # -> signature + cleartext message
        bad_smsg_message = bytes([(b + 1) if b < 255 else 0 for b in bytearray(smsg.message)])
        bad_smsg_signature = bytes([(b + 1) if b < 255 else 0 for b in bytearray(smsg.signature)])
        bad_smsg = bad_smsg_signature + bad_smsg_message

        assert verify_key.verify(smsg)
        assert verify_key.verify(smsg.signature + smsg.message)
        assert verify_key.verify(smsg.message, smsg.signature)

        assert not verify_key.verify(smsg.message, bad_smsg_signature)
        assert not verify_key.verify(bad_smsg_message, smsg.signature)
        assert not verify_key.verify(bad_smsg_message, bad_smsg_signature)
        assert not verify_key.verify(bad_smsg)

    def test_signing_string_parity(self):
        signing_key = Ed25519Key(SIGNING_KEY, algorithm=ALGORITHMS.EdDSA, use=USAGES.PRIVATE)
        verify_key = signing_key.public_key()

        msg = 'test'
        smsg = signing_key.sign(msg)  # -> signature + cleartext message
        bad_smsg_message = bytes([(b + 1) if b < 255 else 0 for b in bytearray(smsg.message)])
        bad_smsg_signature = bytes([(b + 1) if b < 255 else 0 for b in bytearray(smsg.signature)])
        bad_smsg = bad_smsg_signature + bad_smsg_message

        assert verify_key.verify(smsg)
        assert verify_key.verify(smsg.signature + smsg.message)
        assert verify_key.verify(smsg.message, smsg.signature)

        assert not verify_key.verify(smsg.message, bad_smsg_signature)
        assert not verify_key.verify(bad_smsg_message, smsg.signature)
        assert not verify_key.verify(bad_smsg_message, bad_smsg_signature)
        assert not verify_key.verify(bad_smsg)
