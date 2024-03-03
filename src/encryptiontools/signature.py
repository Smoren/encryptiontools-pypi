import json
import rsa

from encryptiontools.exceptions import SigningError, VerificationError


class Signer:
    """
    Sign data using private key.
    """
    _private_key: rsa.PrivateKey

    @classmethod
    def create(cls, private_key_bytes: bytes) -> "Signer":
        """
        Create signer with private key given as bytes.

        :param private_key_bytes: private key as bytes
        :return: signer instance
        """
        return cls(rsa.PrivateKey.load_pkcs1(private_key_bytes))

    def __init__(self, private_key: rsa.PrivateKey):
        self._private_key = private_key

    def sign(self, data) -> bytes:
        """
        Sign data using private key.

        :param data: data to sign (any type that can be encoded in JSON format)
        :return: signature
        :raise: SigningError if signing fails
        """
        try:
            message = json.dumps(data)
            return rsa.sign(message.encode(), self._private_key, 'SHA-256')
        except Exception as e:
            raise SigningError(str(e))


class Verifier:
    """
    Verify data using public key and signature.
    """
    _public_key: rsa.PublicKey

    @classmethod
    def create(cls, public_key_bytes: bytes) -> "Verifier":
        """
        Create verifier with public key given as bytes.

        :param public_key_bytes: public key as bytes
        :return: verifier instance
        """
        return cls(rsa.PublicKey.load_pkcs1(public_key_bytes))

    def __init__(self, public_key: rsa.PublicKey):
        self._public_key = public_key

    def verify(self, data, signature: bytes):
        """
        Verify data using public key and signature.

        :param data: data to verify
        :param signature: signature
        :raise: VerificationError if verification fails or if signature is invalid
        """
        try:
            message = json.dumps(data)
            return rsa.verify(message.encode(), signature, self._public_key)
        except Exception as e:
            raise VerificationError(str(e))
