"""
Module: integrity.py
Description: Provides HMAC generation and verification to detect corruption of data or names.
"""

import logging
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


def generate_hmac(data: str | bytes, key: bytes) -> str:
    try:
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data_bytes)
        return h.finalize().hex()
    except Exception as e:
        logger.error(f"Error generating HMAC: {e}")
        raise


def verify_hmac(data: str | bytes, hmac_value: str, key: bytes) -> bool:
    try:
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data_bytes)
        h.verify(bytes.fromhex(hmac_value))
        return True
    except Exception:
        logger.warning(f"HMAC verification failed for data='{data}'.")
        return False
