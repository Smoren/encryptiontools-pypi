from encryptiontools.signature import Signer, Verifier
from encryptiontools.encryption import AsymmetricEncrypter, AsymmetricDecrypter, SymmetricEncrypter, CombinedEncrypter, \
    CombinedDecrypter
from encryptiontools.exceptions import VerificationError
from encryptiontools.tools import generate_key_pair


def test_asymmetric_encrypter_example():
    private_key, public_key = generate_key_pair(512)

    data = {'message': 'hello asymmetric encryption'}

    encrypter = AsymmetricEncrypter.create(public_key.save_pkcs1())  # or AsymmetricEncrypter(public_key)
    decrypter = AsymmetricDecrypter.create(private_key.save_pkcs1())  # or AsymmetricDecrypter(private_key)

    encrypted = encrypter.encrypt(data)
    decrypted = decrypter.decrypt(encrypted)

    assert decrypted['message'] == 'hello asymmetric encryption'


def test_symmetric_encrypter_example():
    key = b'0123456789abcdef'

    data = {'message': 'hello symmetric encryption'}

    encrypter = SymmetricEncrypter.create(key)  # or SymmetricEncrypter(key)

    encrypted = encrypter.encrypt(data)
    decrypted = encrypter.decrypt(encrypted)

    assert decrypted['message'] == 'hello symmetric encryption'


def test_combined_encrypter_example():
    private_key, public_key = generate_key_pair(512)

    data = {'message': 'hello combined encryption'}

    encrypter = CombinedEncrypter.create(public_key.save_pkcs1())  # or CombinedEncrypter(public_key)
    decrypter = CombinedDecrypter.create(private_key.save_pkcs1())  # or CombinedDecrypter(private_key)

    encrypted = encrypter.encrypt(data)
    decrypted = decrypter.decrypt(encrypted)

    assert decrypted['message'] == 'hello combined encryption'


def test_sign_and_verify_example():
    private_key, public_key = generate_key_pair(512)

    data = {'message': 'hello combined encryption'}

    signer = Signer.create(private_key.save_pkcs1())  # or Signer(private_key)
    verifier = Verifier.create(public_key.save_pkcs1())  # or Verifier(public_key)

    signature = signer.sign(data)

    try:
        verifier.verify(data, signature)
        assert True
    except VerificationError:
        assert False
