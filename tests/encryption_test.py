import pytest

from encryptiontools.encryption import AsymmetricEncrypter, AsymmetricDecrypter, SymmetricEncrypter, \
    CombinedEncrypter, CombinedDecrypter
from encryptiontools.exceptions import DecryptionError
from .fixtures import data_provider_for_encryption_input, data_provider_for_key_pair, \
    data_provider_for_key, get_random_string


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
    encrypter = SymmetricEncrypter.create(key)

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


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair_lhs", data_provider_for_key_pair())
@pytest.mark.parametrize("key_pair_rhs", data_provider_for_key_pair())
def test_asymmetric_encrypter_failure(input_data, key_pair_lhs, key_pair_rhs):
    priv_key, _ = key_pair_lhs
    _, pub_key = key_pair_rhs

    encrypter = AsymmetricEncrypter.create(pub_key)
    decrypter = AsymmetricDecrypter.create(priv_key)

    encrypted = encrypter.encrypt(input_data)

    try:
        decrypter.decrypt(encrypted)
        assert False
    except Exception as e:
        assert isinstance(e, DecryptionError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair_lhs", data_provider_for_key_pair())
@pytest.mark.parametrize("key_pair_rhs", data_provider_for_key_pair())
def test_asymmetric_encrypter_failure_broken_data(input_data, key_pair_lhs, key_pair_rhs):
    priv_key, _ = key_pair_lhs
    _, pub_key = key_pair_rhs

    encrypter = AsymmetricEncrypter.create(pub_key)
    decrypter = AsymmetricDecrypter.create(priv_key)

    encrypted = encrypter.encrypt(input_data)
    prefix = get_random_string()
    encrypted = prefix.encode() + encrypted

    try:
        decrypter.decrypt(encrypted)
        assert False
    except Exception as e:
        assert isinstance(e, DecryptionError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_lhs", data_provider_for_key())
@pytest.mark.parametrize("key_rhs", data_provider_for_key())
def test_symmetric_encrypter_failure(input_data, key_lhs, key_rhs):
    if key_lhs == key_rhs:
        return

    encrypter = SymmetricEncrypter.create(key_lhs)
    decrypter = SymmetricEncrypter.create(key_rhs)

    encrypted = encrypter.encrypt(input_data)

    try:
        decrypter.decrypt(encrypted)
        assert False
    except Exception as e:
        assert isinstance(e, DecryptionError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key", data_provider_for_key())
def test_symmetric_encrypter_failure_broken_data(input_data, key):
    encrypter = SymmetricEncrypter.create(key)
    encrypted = encrypter.encrypt(input_data)
    prefix = get_random_string()
    encrypted = prefix.encode() + encrypted

    try:
        encrypter.decrypt(encrypted)
        assert False
    except Exception as e:
        assert isinstance(e, DecryptionError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair_lhs", data_provider_for_key_pair())
@pytest.mark.parametrize("key_pair_rhs", data_provider_for_key_pair())
def test_combined_encrypter_failure(input_data, key_pair_lhs, key_pair_rhs):
    priv_key, _ = key_pair_lhs
    _, pub_key = key_pair_rhs

    encrypter = CombinedEncrypter.create(pub_key)
    decrypter = CombinedDecrypter.create(priv_key)

    encrypted = encrypter.encrypt(input_data)

    try:
        decrypter.decrypt(encrypted)
        assert False
    except Exception as e:
        assert isinstance(e, DecryptionError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair_lhs", data_provider_for_key_pair())
@pytest.mark.parametrize("key_pair_rhs", data_provider_for_key_pair())
def test_combined_encrypter_failure_broken_data(input_data, key_pair_lhs, key_pair_rhs):
    priv_key, _ = key_pair_lhs
    _, pub_key = key_pair_rhs

    encrypter = CombinedEncrypter.create(pub_key)
    decrypter = CombinedDecrypter.create(priv_key)

    encrypted = encrypter.encrypt(input_data)
    prefix = get_random_string()
    encrypted = prefix.encode() + encrypted

    try:
        decrypter.decrypt(encrypted)
        assert False
    except Exception as e:
        assert isinstance(e, DecryptionError)
