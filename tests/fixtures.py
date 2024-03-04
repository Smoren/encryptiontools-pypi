import random
import string
from typing import Generator, Tuple

from encryptiontools.utils import generate_key_pair


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
    yield 's' * 3000
    yield '1' * 100 * 1000


def get_key_pair(key_len: int) -> [bytes, bytes]:
    pub_key, priv_key = generate_key_pair(key_len)
    return pub_key.save_pkcs1(), priv_key.save_pkcs1()


def data_provider_for_key_pair(min_degree: int = 7, max_degree: int = 10) -> Generator[Tuple[bytes, bytes], None, None]:
    for i in range(min_degree, max_degree+1):
        yield get_key_pair(2**i)


def data_provider_for_key() -> Generator[bytes, None, None]:
    yield b''
    yield b'1'
    yield b'!QAZ2wsx#EDC!QAZ'
    yield b'1234567890123456789012345678901234567890'


def get_random_string() -> str:
    return str(''.join(random.choice(string.ascii_letters + string.digits + string.punctuation)
                       for _ in range(random.randint(1, 10))))
