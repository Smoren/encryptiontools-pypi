from typing import Generator, Tuple

from encryptiontools.tools import generate_key_pair


def data_provider_for_encryption_input() -> Generator[dict, None, None]:
    yield None
    yield 1
    yield 1.1
    yield True
    yield False
    yield []
    yield [1, 2, 3]
    yield [1, 2, 3, {}, {'a': True}]
    yield {}
    yield {'test': 1}
    yield {'a': 1, 'b': 'test Русский', 'c': [1, 2, 3], 'd': None, 'e': True, 'f': False, 'g': 1.1}
    yield 's'*3000
    yield '1'*100*1000


def get_key_pair(key_len: int) -> [bytes, bytes]:
    priv_key, pub_key = generate_key_pair(key_len)
    return priv_key.save_pkcs1(), pub_key.save_pkcs1()


def data_provider_for_key_pair() -> Generator[Tuple[bytes, bytes], None, None]:
    yield get_key_pair(128)
    yield get_key_pair(256)
    yield get_key_pair(512)
    yield get_key_pair(1024)


def data_provider_for_key() -> Generator[bytes, None, None]:
    yield b''
    yield b'1'
    yield b'!QAZ2wsx#EDC!QAZ'
    yield b'1234567890123456789012345678901234567890'
