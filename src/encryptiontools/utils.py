from typing import Tuple

import rsa


def generate_key_pair(encryption_rsa_length: int) -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
    """
    Generate RSA key pair for encryption and decryption, signing and verification.

    :param encryption_rsa_length: RSA key length
    :return: RSA key pair: public key, private key
    """
    return rsa.newkeys(encryption_rsa_length)
