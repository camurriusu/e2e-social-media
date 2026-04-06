import base64
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


# --- CA side (called by app) ---
def generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    # Generate CA keypair and self-signed cert at first startup
    keypair = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    cert = (
        x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureShare CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare")]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureShare CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare")]))
        .public_key(keypair.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(keypair.public_key()), critical=False)
        .sign(keypair, hashes.SHA256())
    )
    return keypair, cert


def load_ca(keypair_path: Path, cert_path: Path, passphrase: bytes) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    # Load CA keypair and cert if exists
    keypair = serialization.load_pem_private_key(keypair_path.read_bytes(), password=passphrase)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return keypair, cert


# --- Sender side ---
def verify_cert(pem: str, ca_cert: x509.Certificate) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def encrypt_post(text: str):
    # Generate random AES key and nonce
    aes_key = os.urandom(32)  # Will be RSA encrypted and sent to receiver
    nonce = os.urandom(12)  # Unique per post and used by receiver to decrypt ciphertext
    ciphertext = AESGCM(aes_key).encrypt(nonce, text.encode(), None)
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    return encrypted, aes_key


def encrypt_symmetric_key(aes_key: bytes, public_key: rsa.RSAPublicKey) -> str:
    # Encrypt AES key using RSA public key
    ciphertext = public_key.encrypt(aes_key,
                                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None))
    return base64.b64encode(ciphertext).decode()


# --- Receiver side ---
def generate_keypair(username: str, ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey) -> tuple[
    rsa.RSAPrivateKey, x509.Certificate]:
    keypair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Public key contained in cert
    # Cert: uses username and "SecureShare" as org name,
    #       signed by CA, wrap public key, valid for 1 year,
    #       marked as non-CA and for key encipherment only,
    #       includes fingerprint of CA public key and its own public key
    #       signed using CA's private key.
    cert = (
        x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare")]))
        .issuer_name(ca_cert.subject)
        .public_key(keypair.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            key_encipherment=True,
            content_commitment=False,
            digital_signature=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(keypair.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return keypair, cert


def decrypt_symmetric_key(encrypted: str, private_key: rsa.RSAPrivateKey) -> bytes:
    # Decrypt AES key using RSA private key
    ciphertext = base64.b64decode(encrypted)
    aes_key = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                           label=None))
    return aes_key


def decrypt_post(encrypted: str, aes_key: bytes) -> str:
    # Use AES key to decrypt post
    ciphertext = base64.b64decode(encrypted)
    nonce, ciphertext = ciphertext[:12], ciphertext[12:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode()


def _kdf(password: str, salt: bytes) -> bytes:
    # Take password and salt to derive AES key
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 390000).derive(password.encode())


def encrypt_private_key(private_key: rsa.RSAPrivateKey, password: str) -> tuple[str, str]:
    salt = os.urandom(16)  # Unique per user avoids same aes_key for same password of different user
    aes_key = _kdf(password, salt)
    # Serialise to PEM format before encryption
    private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
    # Encrypt with random nonce
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, private_key_pem, None)
    # SQLite only supports Text so must encode as base64
    # Include nonce in encoding since needed for decryption
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    # Return salt as hex (SQLite can't store bytes) since needed for decryption
    return encrypted, salt.hex()


def decrypt_private_key(encrypted: str, salt_hex: str, password: str) -> rsa.RSAPrivateKey:
    decrypted = base64.b64decode(encrypted)
    nonce, ciphertext = decrypted[:12], decrypted[12:]
    # Recalculate aes_key with same salt
    salt = bytes.fromhex(salt_hex)
    aes_key = _kdf(password, salt)
    # Use aes_key to decrypt ciphertext to get PEM and convert to RSAPrivateKey
    private_key_pem = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    return serialization.load_pem_private_key(private_key_pem, password=None)
