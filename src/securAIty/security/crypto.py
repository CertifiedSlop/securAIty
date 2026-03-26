"""
Cryptography Module

Secure cryptographic operations for the securAIty platform including
AES-GCM encryption, RSA operations, SHA-256 hashing, and bcrypt password hashing.
"""

import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    HashError,
    KeyGenerationError,
    SignatureError,
)


# Constants
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits for GCM
RSA_MIN_KEY_SIZE = 2048
RSA_DEFAULT_KEY_SIZE = 2048
BCRYPT_DEFAULT_ROUNDS = 12
BCRYPT_MIN_ROUNDS = 10
BCRYPT_MAX_ROUNDS = 31
HASH_ALGORITHM = hashes.SHA256()


def generate_secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Uses Python's secrets module for secure random number generation
    suitable for cryptographic operations.

    Args:
        length: Number of random bytes to generate

    Returns:
        Secure random bytes

    Raises:
        CryptoError: If random generation fails
    """
    try:
        return secrets.token_bytes(length)
    except Exception as e:
        raise CryptoError(f"Failed to generate secure random bytes: {e}") from e


def generate_secure_random_hex(length: int) -> str:
    """
    Generate cryptographically secure random hex string.

    Args:
        length: Number of random bytes (hex output will be 2x this length)

    Returns:
        Secure random hex string
    """
    return secrets.token_hex(length)


def generate_aes_key() -> bytes:
    """
    Generate a new AES-256 key.

    Returns:
        32-byte AES key suitable for AES-GCM encryption

    Raises:
        KeyGenerationError: If key generation fails
    """
    try:
        return generate_secure_random_bytes(AES_KEY_SIZE)
    except CryptoError as e:
        raise KeyGenerationError(f"Failed to generate AES key: {e}") from e


def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-256-GCM.

    AES-GCM provides both confidentiality and authenticity.
    The function returns the nonce, ciphertext, and auth tag separately
    to allow flexible storage strategies.

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES encryption key
        associated_data: Optional additional authenticated data (not encrypted)

    Returns:
        Tuple of (nonce, ciphertext, auth_tag)

    Raises:
        EncryptionError: If encryption fails
        ValueError: If key is not 32 bytes
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    try:
        nonce = generate_secure_random_bytes(AES_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

        # Split ciphertext and tag (tag is last 16 bytes)
        ciphertext = ciphertext_with_tag[:-16]
        auth_tag = ciphertext_with_tag[-16:]

        return nonce, ciphertext, auth_tag

    except Exception as e:
        raise EncryptionError(f"AES-GCM encryption failed: {e}") from e


def decrypt_aes_gcm(
    nonce: bytes,
    ciphertext: bytes,
    auth_tag: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Verifies the authentication tag before returning plaintext.
    If the tag doesn't match, decryption fails indicating tampering.

    Args:
        nonce: Nonce used during encryption (12 bytes)
        ciphertext: Encrypted data
        auth_tag: Authentication tag (16 bytes)
        key: 32-byte AES decryption key
        associated_data: Optional additional authenticated data

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption fails or authentication tag invalid
        ValueError: If key is not 32 bytes or nonce is not 12 bytes
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_NONCE_SIZE} bytes, got {len(nonce)}")
    if len(auth_tag) != 16:
        raise ValueError(f"Auth tag must be 16 bytes, got {len(auth_tag)}")

    try:
        aesgcm = AESGCM(key)
        ciphertext_with_tag = ciphertext + auth_tag
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext

    except Exception as e:
        raise DecryptionError(f"AES-GCM decryption failed: {e}") from e


def generate_rsa_keypair(key_size: int = RSA_DEFAULT_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate RSA key pair for asymmetric encryption/signing.

    Args:
        key_size: Key size in bits (minimum 2048)

    Returns:
        Tuple of (private_key, public_key)

    Raises:
        KeyGenerationError: If key generation fails
        ValueError: If key_size is less than 2048
    """
    if key_size < RSA_MIN_KEY_SIZE:
        raise ValueError(f"RSA key size must be at least {RSA_MIN_KEY_SIZE} bits")

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    except Exception as e:
        raise KeyGenerationError(f"Failed to generate RSA keypair: {e}") from e


def serialize_rsa_private_key(private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> bytes:
    """
    Serialize RSA private key to PEM format.

    Args:
        private_key: RSA private key to serialize
        password: Optional password for encryption

    Returns:
        PEM-encoded private key bytes
    """
    encryption_algorithm = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def deserialize_rsa_private_key(pem_data: bytes, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """
    Deserialize RSA private key from PEM format.

    Args:
        pem_data: PEM-encoded private key bytes
        password: Optional password if key is encrypted

    Returns:
        RSA private key object

    Raises:
        CryptoError: If deserialization fails
    """
    try:
        key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend(),
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise CryptoError("Loaded key is not an RSA private key")
        return key

    except Exception as e:
        raise CryptoError(f"Failed to deserialize RSA private key: {e}") from e


def serialize_rsa_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serialize RSA public key to PEM format.

    Args:
        public_key: RSA public key to serialize

    Returns:
        PEM-encoded public key bytes
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_rsa_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """
    Deserialize RSA public key from PEM format.

    Args:
        pem_data: PEM-encoded public key bytes

    Returns:
        RSA public key object

    Raises:
        CryptoError: If deserialization fails
    """
    try:
        key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        if not isinstance(key, rsa.RSAPublicKey):
            raise CryptoError("Loaded key is not an RSA public key")
        return key

    except Exception as e:
        raise CryptoError(f"Failed to deserialize RSA public key: {e}") from e


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """
    Encrypt data using RSA public key with OAEP padding.

    Suitable for encrypting small data like symmetric keys.
    For larger data, use hybrid encryption (encrypt symmetric key with RSA).

    Args:
        public_key: RSA public key for encryption
        plaintext: Data to encrypt

    Returns:
        Encrypted ciphertext

    Raises:
        EncryptionError: If encryption fails
    """
    try:
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

    except Exception as e:
        raise EncryptionError(f"RSA encryption failed: {e}") from e


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    Decrypt data using RSA private key with OAEP padding.

    Args:
        private_key: RSA private key for decryption
        ciphertext: Encrypted data

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption fails
    """
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext

    except Exception as e:
        raise DecryptionError(f"RSA decryption failed: {e}") from e


def sha256_hash(data: bytes) -> bytes:
    """
    Calculate SHA-256 hash of data.

    Args:
        data: Data to hash

    Returns:
        32-byte SHA-256 hash

    Raises:
        HashError: If hashing fails
    """
    try:
        return hashlib.sha256(data).digest()
    except Exception as e:
        raise HashError(f"SHA-256 hashing failed: {e}") from e


def sha256_hex(data: bytes) -> str:
    """
    Calculate SHA-256 hash and return as hex string.

    Args:
        data: Data to hash

    Returns:
        64-character hex string
    """
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(data: bytes, key: bytes) -> bytes:
    """
    Calculate HMAC-SHA256 of data.

    Args:
        data: Data to authenticate
        key: Secret key for HMAC

    Returns:
        32-byte HMAC-SHA256

    Raises:
        HashError: If HMAC calculation fails
    """
    try:
        return hmac.new(key, data, hashlib.sha256).digest()
    except Exception as e:
        raise HashError(f"HMAC-SHA256 calculation failed: {e}") from e


def verify_hmac_sha256(data: bytes, signature: bytes, key: bytes) -> bool:
    """
    Verify HMAC-SHA256 signature using constant-time comparison.

    Args:
        data: Original data
        signature: HMAC signature to verify
        key: Secret key for HMAC

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        expected = hmac_sha256(data, key)
        return secrets.compare_digest(expected, signature)
    except HashError:
        return False


def sign_rsa(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data using RSA private key with PSS padding.

    Args:
        private_key: RSA private key for signing
        data: Data to sign

    Returns:
        Digital signature bytes

    Raises:
        SignatureError: If signing fails
    """
    try:
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature

    except Exception as e:
        raise SignatureError(f"RSA signing failed: {e}") from e


def verify_rsa_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA signature using public key.

    Args:
        public_key: RSA public key for verification
        data: Original signed data
        signature: Signature to verify

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True

    except InvalidSignature:
        return False
    except Exception:
        return False


def hash_password(password: str, rounds: int = BCRYPT_DEFAULT_ROUNDS) -> str:
    """
    Hash password using bcrypt with salt.

    Args:
        password: Plain text password to hash
        rounds: Bcrypt cost factor (10-31)

    Returns:
        Bcrypt hash including salt (60 characters)

    Raises:
        ValueError: If rounds is outside valid range
    """
    if rounds < BCRYPT_MIN_ROUNDS or rounds > BCRYPT_MAX_ROUNDS:
        raise ValueError(f"Bcrypt rounds must be between {BCRYPT_MIN_ROUNDS} and {BCRYPT_MAX_ROUNDS}")

    salt = bcrypt.gensalt(rounds=rounds)
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify password against bcrypt hash using constant-time comparison.

    Args:
        password: Plain text password to verify
        password_hash: Bcrypt hash to verify against

    Returns:
        True if password matches, False otherwise
    """
    try:
        password_bytes = password.encode("utf-8")
        hash_bytes = password_hash.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception:
        return False


def derive_key_from_password(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive encryption key from password using PBKDF2-HMAC-SHA256.

    Args:
        password: User password
        salt: Random salt (should be at least 16 bytes)
        iterations: Number of PBKDF2 iterations

    Returns:
        32-byte derived key suitable for AES encryption

    Raises:
        CryptoError: If key derivation fails
    """
    try:
        password_bytes = password.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return kdf.derive(password_bytes)

    except Exception as e:
        raise CryptoError(f"Key derivation failed: {e}") from e


def timing_safe_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    return secrets.compare_digest(a, b)


def timing_safe_compare_str(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        True if equal, False otherwise
    """
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
