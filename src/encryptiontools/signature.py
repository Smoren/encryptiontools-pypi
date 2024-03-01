import json
import rsa


class Signer:
    _private_key: rsa.PrivateKey

    @classmethod
    def create(cls, private_key_bytes: bytes) -> "Signer":
        return cls(rsa.PrivateKey.load_pkcs1(private_key_bytes))

    def __init__(self, private_key: rsa.PrivateKey):
        self._private_key = private_key

    def sign(self, data) -> bytes:
        message = json.dumps(data)
        return rsa.sign(message.encode(), self._private_key, 'SHA-256')


class Verifier:
    _public_key: rsa.PublicKey

    @classmethod
    def create(cls, public_key_bytes: bytes) -> "Verifier":
        return cls(rsa.PublicKey.load_pkcs1(public_key_bytes))

    def __init__(self, public_key: rsa.PublicKey):
        self._public_key = public_key

    def verify(self, data, signature: bytes):
        message = json.dumps(data)
        return rsa.verify(message.encode(), signature, self._public_key)
