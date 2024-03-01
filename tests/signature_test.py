import pytest

from encryptiontools.signature import Signer, Verifier
from .fixtures import data_provider_for_encryption_input, data_provider_for_key_pair


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair", data_provider_for_key_pair())
def test_signer_verifier_success(input_data, key_pair):
    priv_key, pub_key = key_pair

    signer = Signer.create(priv_key)
    verifier = Verifier.create(pub_key)

    signature = signer.sign(input_data)
    verifier.verify(input_data, signature)

    assert True
