import base64
import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: str, password: str) -> str:
    """Encrypts string data using AES-256-CBC with PKCS7 padding."""
    # 1. Generate salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # 2. Derive 256-bit key
    key = derive_key(password, salt)
    
    # 3. Apply PKCS7 Padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    # 4. Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 5. Combine and encode to Base64 for the LSB stego module
    # We store [SALT (16) + IV (16) + CIPHERTEXT]
    combined = salt + iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_data(encrypted_b64: str, password: str) -> str:
    """Decrypts AES-256-CBC data and removes PKCS7 padding."""
    try:
        # 1. Decode Base64 and split components
        combined = base64.b64decode(encrypted_b64)
        salt = combined[:16]
        iv = combined[16:32]
        ciphertext = combined[32:]
        
        # 2. Re-derive the key using the stored salt
        key = derive_key(password, salt)
        
        # 3. Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 4. Remove PKCS7 Padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data.decode('utf-8')
    except Exception as e:
        # This usually triggers if the password is wrong or data is corrupted
        raise ValueError("Decryption failed. Invalid passphrase or corrupted payload.")