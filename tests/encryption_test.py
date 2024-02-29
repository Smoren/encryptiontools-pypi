import pytest

from encryptiontools.encryption import AsymmetricEncrypter, AsymmetricDecrypter, SymmetricEncrypter, CombinedEncrypter, \
    CombinedDecrypter
from .fixtures import data_provider_for_encryption_input, data_provider_for_key_pair, \
    data_provider_for_key


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair", data_provider_for_key_pair())
def test_asymmetric_encrypter(input_data, key_pair):
    priv_key, pub_key = key_pair

    encrypter = AsymmetricEncrypter.create(pub_key)
    decrypter = AsymmetricDecrypter.create(priv_key)

    encrypted = encrypter.encrypt(input_data)
    decrypted = decrypter.decrypt(encrypted)

    assert input_data == decrypted
    assert input_data != encrypted


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key", data_provider_for_key())
def test_symmetric_encrypter(input_data, key):
    encrypter = SymmetricEncrypter(key)

    encrypted = encrypter.encrypt(input_data)
    decrypted = encrypter.decrypt(encrypted)

    assert input_data == decrypted
    assert input_data != encrypted

    decrypter = SymmetricEncrypter(key)
    decrypted = decrypter.decrypt(encrypted)
    assert input_data == decrypted


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair", data_provider_for_key_pair())
def test_combined_encrypter(input_data, key_pair):
    priv_key, pub_key = key_pair

    encrypter = CombinedEncrypter.create(pub_key)
    decrypter = CombinedDecrypter.create(priv_key)

    encrypted = encrypter.encrypt(input_data)
    decrypted = decrypter.decrypt(encrypted)

    assert input_data == decrypted
    assert input_data != encrypted
