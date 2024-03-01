import json
import random
import string

import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from encryptiontools.exceptions import DecryptionError


class AsymmetricEncrypter:
    public_key: rsa.PublicKey

    @classmethod
    def create(cls, pub_key_bytes: bytes) -> "AsymmetricEncrypter":
        public_key = rsa.PublicKey.load_pkcs1(pub_key_bytes)
        return cls(public_key)

    def __init__(self, pub_key: rsa.PublicKey):
        self.public_key = pub_key

    def encrypt(self, data) -> bytes:
        str_to_encrypt = json.dumps(data)
        result = []

        batch_size = self.public_key.n.bit_length() // 8 - 11
        for n in range(0, len(str_to_encrypt), batch_size):
            part = str_to_encrypt[n:n+batch_size]
            result.append(rsa.encrypt(part.encode("ascii"), self.public_key))
        return b''.join(result)


class AsymmetricDecrypter:
    private_key: rsa.PrivateKey

    @classmethod
    def create(cls, priv_key_bytes: bytes) -> "AsymmetricDecrypter":
        private_key = rsa.PrivateKey.load_pkcs1(priv_key_bytes)
        return cls(private_key)

    def __init__(self, priv_key: rsa.PrivateKey):
        self.private_key = priv_key

    def decrypt(self, data: bytes):
        try:
            result = []
            batch_size = self.private_key.n.bit_length() // 8
            for n in range(0, len(data), batch_size):
                part = data[n:n+batch_size]
                result.append(rsa.decrypt(part, self.private_key).decode("ascii"))
            return json.loads(''.join(result))
        except rsa.pkcs1.DecryptionError as e:
            raise DecryptionError(str(e))


class SymmetricEncrypter:
    _key: bytes

    @classmethod
    def create(cls, key: bytes) -> "SymmetricEncrypter":
        return cls(key)

    def __init__(self, key: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            iterations=100,
            backend=default_backend()
        )

        self._key = kdf.derive(key)

    def encrypt(self, data):
        str_to_encrypt = json.dumps(data)
        cipher = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())
        encrypter = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(str_to_encrypt.encode()) + padder.finalize()
        ciphertext = encrypter.update(padded_data) + encrypter.finalize()
        return ciphertext

    def decrypt(self, data: bytes):
        try:
            cipher = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())
            decrypter = cipher.decryptor()
            decrypted_data = decrypter.update(data) + decrypter.finalize()
            padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            unpadded_data = padder.update(decrypted_data) + padder.finalize()
            return json.loads(unpadded_data.decode())
        except Exception as e:
            raise DecryptionError(str(e))


class CombinedEncrypter:
    _encrypter: SymmetricEncrypter
    _internal_key_encrypted: bytes

    @classmethod
    def create(cls, pub_key_bytes: bytes, internal_key_length: int = 512) -> "CombinedEncrypter":
        public_key = rsa.PublicKey.load_pkcs1(pub_key_bytes)
        return cls(public_key, internal_key_length)

    def __init__(self, public_key: rsa.PublicKey, internal_key_length: int = 512):
        internal_key = self._generate_random_string(internal_key_length)
        self._internal_key_encrypted = AsymmetricEncrypter(public_key).encrypt(internal_key)
        self._encrypter = SymmetricEncrypter(internal_key.encode('utf-8'))

    def encrypt(self, data):
        return self._get_prefix() + self._encrypter.encrypt(data)

    def _get_prefix(self) -> bytes:
        return str(len(self._internal_key_encrypted)).encode() + str('_').encode() + self._internal_key_encrypted

    @staticmethod
    def _generate_random_string(key_length) -> str:
        return ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(key_length)])


class CombinedDecrypter:
    _decrypter: SymmetricEncrypter
    _private_key: rsa.PrivateKey

    @classmethod
    def create(cls, priv_key_bytes: bytes) -> "CombinedDecrypter":
        private_key = rsa.PrivateKey.load_pkcs1(priv_key_bytes)
        return cls(private_key)

    def __init__(self, private_key: rsa.PrivateKey):
        self._private_key = private_key

    def decrypt(self, data):
        try:
            internal_key_encrypted, data_encrypted = self._parse_prefix(data)
            internal_key = AsymmetricDecrypter(self._private_key).decrypt(internal_key_encrypted)
            return SymmetricEncrypter(internal_key.encode()).decrypt(data_encrypted)
        except Exception as e:
            raise DecryptionError(str(e))

    @staticmethod
    def _parse_prefix(data: bytes) -> [bytes, bytes]:
        prefix = []
        for b in data:
            if not ord('0') <= b <= ord('9'):
                break
            prefix.append(chr(b))

        if not len(prefix):
            raise DecryptionError('Cannot get key length')

        internal_key_start = len(prefix) + 1
        data_start = int(''.join(prefix)) + internal_key_start
        return data[internal_key_start:data_start], data[data_start:]
