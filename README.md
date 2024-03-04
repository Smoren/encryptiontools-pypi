# Encryption Tools for Python 3

[![PyPI package](https://img.shields.io/badge/pip%20install-encryptiontools-brightgreen)](https://pypi.org/project/encryptiontools/)
[![version number](https://img.shields.io/pypi/v/encryptiontools?color=green&label=version)](https://github.com/Smoren/encryptiontools-pypi/releases)
[![Coverage Status](https://coveralls.io/repos/github/Smoren/encryptiontools-pypi/badge.svg?branch=master)](https://coveralls.io/github/Smoren/encryptiontools-pypi?branch=master)
[![Actions Status](https://github.com/Smoren/encryptiontools-pypi/workflows/Test/badge.svg)](https://github.com/Smoren/encryptiontools-pypi/actions)
[![License](https://img.shields.io/github/license/Smoren/encryptiontools-pypi)](https://github.com/Smoren/encryptiontools-pypi/blob/master/LICENSE)

Tools for encryption and decryption, signing and verification. Use symmetric and asymmetric (RSA-based) encryption.

## Installation

```
pip install encryptiontools
```

## Usage

### Asymmetric encryption and decryption

```python
from encryptiontools.encryption import AsymmetricEncrypter, AsymmetricDecrypter
from encryptiontools.utils import generate_key_pair

public_key, private_key = generate_key_pair(512)

data = {'message': 'hello asymmetric encryption'}

encrypter = AsymmetricEncrypter.create(public_key.save_pkcs1())  # or AsymmetricEncrypter(public_key)
decrypter = AsymmetricDecrypter.create(private_key.save_pkcs1())  # or AsymmetricDecrypter(private_key)

encrypted = encrypter.encrypt(data)
decrypted = decrypter.decrypt(encrypted)

assert decrypted['message'] == 'hello asymmetric encryption'
```

### Symmetric encryption and decryption

```python
from encryptiontools.encryption import SymmetricEncrypter

key = b'0123456789abcdef'

data = {'message': 'hello symmetric encryption'}

encrypter = SymmetricEncrypter.create(key)  # or SymmetricEncrypter(key)

encrypted = encrypter.encrypt(data)
decrypted = encrypter.decrypt(encrypted)

assert decrypted['message'] == 'hello symmetric encryption'
```

### Combined encryption and decryption

Asymmetric key pair is used to encrypt/decrypt internal (symmetric) key, internal key is used to decrypt data.

```python
from encryptiontools.encryption import CombinedEncrypter, CombinedDecrypter
from encryptiontools.utils import generate_key_pair

public_key, private_key = generate_key_pair(512)

data = {'message': 'hello combined encryption'}

encrypter = CombinedEncrypter.create(public_key.save_pkcs1())  # or CombinedEncrypter(public_key)
decrypter = CombinedDecrypter.create(private_key.save_pkcs1())  # or CombinedDecrypter(private_key)

encrypted = encrypter.encrypt(data)
decrypted = decrypter.decrypt(encrypted)

assert decrypted['message'] == 'hello combined encryption'
```

### Signing and verification

```python
from encryptiontools.signature import Signer, Verifier
from encryptiontools.utils import generate_key_pair
from encryptiontools.exceptions import VerificationError

public_key, private_key = generate_key_pair(512)

data = {'message': 'hello signing and verification'}

signer = Signer.create(private_key.save_pkcs1())  # or Signer(private_key)
verifier = Verifier.create(public_key.save_pkcs1())  # or Verifier(public_key)

signature = signer.sign(data)

try:
  verifier.verify(data, signature)
  assert True
except VerificationError:
  assert False
```
