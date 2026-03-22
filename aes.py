import base64
import os
import hmac
import hashlib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- FORMAT ---
# Encrypted payload layout (all base64-encoded):
#   [SALT 16B][IV 16B][HMAC 32B][CIPHERTEXT]

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from a password using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def derive_hmac_key(password: str, salt: bytes) -> bytes:
    """Derives a separate 32-byte HMAC key from the same password with a different salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b"hmac",   # Domain separation from the AES key
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: str, password: str) -> str:
    """
    Encrypts string data using AES-256-CBC with PKCS7 padding.
    Appends an HMAC-SHA256 tag for integrity verification.
    Layout: SALT(16) + IV(16) + HMAC(32) + CIPHERTEXT
    """
    # 1. Generate salt and IV
    salt = os.urandom(16)
    iv   = os.urandom(16)

    # 2. Derive AES key and HMAC key from the password
    aes_key  = derive_key(password, salt)
    hmac_key = derive_hmac_key(password, salt)

    # 3. Apply PKCS7 padding and encrypt
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 4. Compute HMAC over the ciphertext for integrity protection
    tag = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()  # 32 bytes

    # 5. Pack: SALT + IV + HMAC_TAG + CIPHERTEXT, then base64-encode
    combined = salt + iv + tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_data(encrypted_b64: str, password: str) -> str:
    """
    Decrypts AES-256-CBC data, verifying the HMAC tag before decryption.
    Raises ValueError on wrong password, tampered data, or corrupted payload.
    """
    try:
        # 1. Decode and unpack components
        combined   = base64.b64decode(encrypted_b64)
        salt       = combined[:16]
        iv         = combined[16:32]
        stored_tag = combined[32:64]   # HMAC is 32 bytes
        ciphertext = combined[64:]

        # 2. Re-derive both keys
        aes_key  = derive_key(password, salt)
        hmac_key = derive_hmac_key(password, salt)

        # 3. Verify HMAC BEFORE attempting decryption (Encrypt-then-MAC)
        expected_tag = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(stored_tag, expected_tag):
            raise ValueError("INTEGRITY_FAILURE: Payload has been tampered with or the passphrase is incorrect.")

        # 4. Decrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode('utf-8')

    except ValueError:
        raise
    except Exception:
        raise ValueError("DECRYPTION_FAILED: Invalid passphrase or corrupted payload.")