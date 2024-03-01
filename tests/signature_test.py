import random
import string

import pytest

from encryptiontools.exceptions import SigningError, VerificationError
from encryptiontools.signature import Signer, Verifier
from .fixtures import data_provider_for_encryption_input, data_provider_for_key_pair


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair", data_provider_for_key_pair(min_degree=9))
def test_signer_verifier_success(input_data, key_pair):
    priv_key, pub_key = key_pair

    signer = Signer.create(priv_key)
    verifier = Verifier.create(pub_key)

    signature = signer.sign(input_data)
    verifier.verify(input_data, signature)

    assert True


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair", data_provider_for_key_pair(min_degree=5, max_degree=8))
def test_signer_verifier_failure_short_key(input_data, key_pair):
    priv_key, pub_key = key_pair

    signer = Signer.create(priv_key)

    try:
        signer.sign(input_data)
        assert False
    except Exception as e:
        assert isinstance(e, SigningError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair_lhs", data_provider_for_key_pair(min_degree=9))
@pytest.mark.parametrize("key_pair_rhs", data_provider_for_key_pair(min_degree=9))
def test_signer_verifier_failure_different_keys(input_data, key_pair_lhs, key_pair_rhs):
    priv_key, _ = key_pair_lhs
    _, pub_key = key_pair_rhs

    signer = Signer.create(priv_key)
    verifier = Verifier.create(pub_key)

    signature = signer.sign(input_data)

    try:
        verifier.verify(input_data, signature)
        assert False
    except Exception as e:
        assert isinstance(e, VerificationError)


@pytest.mark.parametrize("input_data", data_provider_for_encryption_input())
@pytest.mark.parametrize("key_pair", data_provider_for_key_pair(min_degree=9))
def test_signer_verifier_failure_bad_signature(input_data, key_pair):
    priv_key, pub_key = key_pair

    signer = Signer.create(priv_key)
    verifier = Verifier.create(pub_key)

    signature = signer.sign(input_data)
    sep = len(signature) // 2
    signature = signature[:sep] + bytes(signature[sep]+1) + signature[sep+1:]

    try:
        verifier.verify(input_data, signature)
        assert False
    except Exception as e:
        assert isinstance(e, VerificationError)
