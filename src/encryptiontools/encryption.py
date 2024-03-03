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
    """
    Encrypt data using public key.
    """
    _public_key: rsa.PublicKey

    @classmethod
    def create(cls, public_key_bytes: bytes) -> "AsymmetricEncrypter":
        """
        Create encrypter with public key given as bytes.

        :param public_key_bytes: public key as bytes
        :return: encrypter instance
        """
        return cls(rsa.PublicKey.load_pkcs1(public_key_bytes))

    def __init__(self, public_key: rsa.PublicKey):
        self._public_key = public_key

    def encrypt(self, data) -> bytes:
        """
        Encrypt data using public key.

        :param data: data to encrypt (any type that can be encoded in JSON format)
        :return: encrypted data
        """
        str_to_encrypt = json.dumps(data)
        result = []

        batch_size = self._public_key.n.bit_length() // 8 - 11
        for n in range(0, len(str_to_encrypt), batch_size):
            part = str_to_encrypt[n:n+batch_size]
            result.append(rsa.encrypt(part.encode("ascii"), self._public_key))
        return b''.join(result)


class AsymmetricDecrypter:
    """
    Decrypt data using private key.
    """
    _private_key: rsa.PrivateKey

    @classmethod
    def create(cls, private_key_bytes: bytes) -> "AsymmetricDecrypter":
        """
        Create decrypter with private key given as bytes.

        :param private_key_bytes: private key as bytes
        :return: decrypter instance
        """
        return cls(rsa.PrivateKey.load_pkcs1(private_key_bytes))

    def __init__(self, private_key: rsa.PrivateKey):
        self._private_key = private_key

    def decrypt(self, data: bytes):
        """
        Decrypt data using private key.

        :param data: data to decrypt
        :return: decrypted data (JSON-decoded)
        :raise: DecryptionError if decryption fails
        """
        try:
            result = []
            batch_size = self._private_key.n.bit_length() // 8
            for n in range(0, len(data), batch_size):
                part = data[n:n+batch_size]
                result.append(rsa.decrypt(part, self._private_key).decode("ascii"))
            return json.loads(''.join(result))
        except rsa.pkcs1.DecryptionError as e:
            raise DecryptionError(str(e))


class SymmetricEncrypter:
    """
    Encrypt and decrypt data using symmetric key.
    """
    _key: bytes

    @classmethod
    def create(cls, key: bytes) -> "SymmetricEncrypter":
        """
        Create encrypter with symmetric key given as bytes.

        :param key: symmetric key
        :return: encrypter instance
        """
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
        """
        Encrypt data using symmetric key.

        :param data: data to encrypt (any type that can be encoded in JSON format)
        :return: encrypted data
        """
        str_to_encrypt = json.dumps(data)
        cipher = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())
        encrypter = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(str_to_encrypt.encode()) + padder.finalize()
        ciphertext = encrypter.update(padded_data) + encrypter.finalize()
        return ciphertext

    def decrypt(self, data: bytes):
        """
        Decrypt data using symmetric key.

        :param data: data to decrypt
        :return: decrypted data (JSON-decoded)
        :raise: DecryptionError if decryption fails
        """
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
    """
    Encrypt data using asymmetric and symmetric keys.

    Asymmetric key is used to encrypt internal (symmetric) key, internal key is used to encrypt data.
    """
    _encrypter: SymmetricEncrypter
    _internal_key_encrypted: bytes

    @classmethod
    def create(cls, pub_key_bytes: bytes, internal_key_length: int = 512) -> "CombinedEncrypter":
        """
        Create encrypter with public key given as bytes.

        :param pub_key_bytes: public key as bytes
        :param internal_key_length: length of symmetric key

        :return: encrypter instance
        """
        public_key = rsa.PublicKey.load_pkcs1(pub_key_bytes)
        return cls(public_key, internal_key_length)

    def __init__(self, public_key: rsa.PublicKey, internal_key_length: int = 512):
        """
        :param public_key: public key
        :param internal_key_length: length of symmetric key
        """
        internal_key = self._generate_random_string(internal_key_length)
        self._internal_key_encrypted = AsymmetricEncrypter(public_key).encrypt(internal_key)
        self._encrypter = SymmetricEncrypter(internal_key.encode('utf-8'))

    def encrypt(self, data):
        """
        Encrypt data using asymmetric and symmetric keys.

        :param data: data to encrypt (any type that can be encoded in JSON format)
        :return: encrypted data
        """
        return self._get_prefix() + self._encrypter.encrypt(data)

    def _get_prefix(self) -> bytes:
        """
        Get prefix of encrypted data.

        The prefix is used to store the encrypted internal (symmetric) key.

        :return: prefix
        """
        return str(len(self._internal_key_encrypted)).encode() + str('_').encode() + self._internal_key_encrypted

    @staticmethod
    def _generate_random_string(key_length) -> str:
        """
        Generate random string.

        :param key_length: length of string
        :return: random string
        """
        return ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(key_length)])


class CombinedDecrypter:
    """
    Decrypt data using asymmetric and symmetric keys.

    Asymmetric key is used to decrypt internal (symmetric) key, internal key is used to decrypt data.
    """
    _decrypter: SymmetricEncrypter
    _private_key: rsa.PrivateKey

    @classmethod
    def create(cls, priv_key_bytes: bytes) -> "CombinedDecrypter":
        """
        Create decrypter with private key given as bytes.

        :param priv_key_bytes: private key as bytes
        :return: decrypter instance
        """
        return cls(rsa.PrivateKey.load_pkcs1(priv_key_bytes))

    def __init__(self, private_key: rsa.PrivateKey):
        self._private_key = private_key

    def decrypt(self, data):
        """
        Decrypt data using asymmetric and symmetric keys.

        :param data: data to decrypt
        :return: decrypted data (JSON-decoded)
        :raise: DecryptionError if decryption fails
        """
        try:
            internal_key_encrypted, data_encrypted = self._parse_prefix(data)
            internal_key = AsymmetricDecrypter(self._private_key).decrypt(internal_key_encrypted)
            return SymmetricEncrypter(internal_key.encode()).decrypt(data_encrypted)
        except Exception as e:
            raise DecryptionError(str(e))

    @staticmethod
    def _parse_prefix(data: bytes) -> [bytes, bytes]:
        """
        Parse prefix of encrypted data.

        The prefix is used to store the encrypted internal (symmetric) key.

        :param data: encrypted data
        :return: encoded internal key and encrypted data
        :raise: DecryptionError if prefix cannot be parsed
        """
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
