import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization


def kdf(password: str, salt:bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 390000).derive(password.encode())

def encrypt_pk(pk: rsa.RSAPrivateKey, password: str) -> tuple[str, bytes]:
    salt = os.urandom(16) # Unique per user avoids same aes_key for same password
    aes_key = kdf(password, salt)
    # Serialise to PEM format before encryption
    pem = pk.private_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PrivateFormat.PKCS8,
                           encryption_algorithm=serialization.NoEncryption())
    # Encrypt with random nonce
    nonce = os.urandom()
    ciphertext = AESGCM(aes_key).encrypt(nonce, pem, None)
    # SQLite only supports Text so must encode as base64
    # Include nonce in encoding since needed for decryption
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    # Return salt since needed for decryption
    return encrypted, salt

def decrypt_pk(encrypted: str, salt: bytes, password: str) -> rsa.RSAPrivateKey:
    decrypted = base64.b64decode(encrypted)
    nonce, ciphertext = decrypted[:12], decrypted[12:]
    # Recalculate aes_key with same salt
    aes_key = kdf(password, salt)
    # Use aes_key to decrypt ciphertext to get PEM and convert to RSAPrivateKey
    pem = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    return serialization.load_pem_private_key(pem, password=None)