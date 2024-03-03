class DecryptionError(Exception):
    """
    Exception raised when data cannot be decrypted.
    """
    pass


class SigningError(Exception):
    """
    Exception raised when data cannot be signed.
    """
    pass


class VerificationError(Exception):
    """
    Exception raised when data cannot be verified with public key and signature.
    """
    pass
