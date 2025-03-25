"""
Module: encryption.py
Description: Uses the cryptography.fernet.Fernet for symmetric encryption of content.
"""

import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def generate_key() -> bytes:
    key = Fernet.generate_key()
    logger.info("Encryption key generated.")
    return key


def encrypt_data(plaintext: str, key: bytes) -> str:
    try:
        f = Fernet(key)
        encrypted = f.encrypt(plaintext.encode("utf-8"))
        return encrypted.decode("utf-8")
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise


def decrypt_data(ciphertext: str, key: bytes) -> str:
    try:
        f = Fernet(key)
        decrypted = f.decrypt(ciphertext.encode("utf-8"))
        return decrypted.decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise
