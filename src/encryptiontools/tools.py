from typing import Tuple

import rsa


def generate_key_pair(encryption_rsa_length: int) -> Tuple[rsa.PrivateKey, rsa.PublicKey]:
    """
    Generate RSA key pair for encryption and decryption, signing and verification.

    :param encryption_rsa_length: RSA key length
    :return: RSA key pair: private key, public key
    """
    public_key, private_key = rsa.newkeys(encryption_rsa_length)
    return private_key, public_key
