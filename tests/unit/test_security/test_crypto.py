"""
Unit tests for cryptographic functions in securAIty security module.

Tests cover AES-GCM encryption, RSA operations, hashing, HMAC,
password hashing, and constant-time comparisons.
"""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from securAIty.security.crypto import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    BCRYPT_DEFAULT_ROUNDS,
    RSA_MIN_KEY_SIZE,
    decrypt_aes_gcm,
    derive_key_from_password,
    encrypt_aes_gcm,
    generate_aes_key,
    generate_rsa_keypair,
    generate_secure_random_bytes,
    generate_secure_random_hex,
    hash_password,
    hmac_sha256,
    rsa_decrypt,
    rsa_encrypt,
    serialize_rsa_private_key,
    serialize_rsa_public_key,
    sha256_hash,
    sha256_hex,
    sign_rsa,
    timing_safe_compare,
    timing_safe_compare_str,
    verify_hmac_sha256,
    verify_password,
    verify_rsa_signature,
)
from securAIty.security.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    HashError,
    KeyGenerationError,
    SignatureError,
)


class TestGenerateSecureRandomBytes:
    """Tests for generate_secure_random_bytes function."""

    def test_generate_secure_random_bytes_returns_correct_length(self) -> None:
        """Returns bytes of requested length."""
        result = generate_secure_random_bytes(16)
        assert len(result) == 16

        result = generate_secure_random_bytes(32)
        assert len(result) == 32

        result = generate_secure_random_bytes(1)
        assert len(result) == 1

    def test_generate_secure_random_bytes_different_each_call(self) -> None:
        """Returns different values on each call."""
        values = [generate_secure_random_bytes(16) for _ in range(100)]
        unique_values = set(values)
        assert len(unique_values) == 100

    def test_generate_secure_random_bytes_zero_length(self) -> None:
        """Returns empty bytes for zero length."""
        result = generate_secure_random_bytes(0)
        assert result == b""

    def test_generate_secure_random_bytes_large_length(self) -> None:
        """Handles large byte generation."""
        result = generate_secure_random_bytes(1024)
        assert len(result) == 1024


class TestGenerateSecureRandomHex:
    """Tests for generate_secure_random_hex function."""

    def test_generate_secure_random_hex_returns_correct_length(self) -> None:
        """Returns hex string of correct length (2x input)."""
        result = generate_secure_random_hex(16)
        assert len(result) == 32

        result = generate_secure_random_hex(1)
        assert len(result) == 2

    def test_generate_secure_random_hex_only_hex_characters(self) -> None:
        """Returns only valid hexadecimal characters."""
        result = generate_secure_random_hex(32)
        assert all(c in "0123456789abcdef" for c in result)

    def test_generate_secure_random_hex_different_each_call(self) -> None:
        """Returns different values on each call."""
        values = [generate_secure_random_hex(16) for _ in range(50)]
        unique_values = set(values)
        assert len(unique_values) == 50


class TestGenerateAesKey:
    """Tests for generate_aes_key function."""

    def test_generate_aes_key_returns_32_bytes(self) -> None:
        """Returns exactly 32 bytes for AES-256."""
        key = generate_aes_key()
        assert len(key) == AES_KEY_SIZE

    def test_generate_aes_key_different_each_call(self) -> None:
        """Returns different keys on each call."""
        key1 = generate_aes_key()
        key2 = generate_aes_key()
        assert key1 != key2

    def test_generate_aes_key_is_random(self) -> None:
        """Generated keys have good entropy."""
        keys = [generate_aes_key() for _ in range(10)]
        assert len(set(keys)) == 10


class TestEncryptDecryptAesGcm:
    """Tests for AES-GCM encryption and decryption."""

    def test_encrypt_decrypt_aes_gcm_roundtrip(self, sample_aes_key: bytes, sample_plaintext: bytes) -> None:
        """Encryption followed by decryption returns original plaintext."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        decrypted = decrypt_aes_gcm(nonce, ciphertext, auth_tag, sample_aes_key)
        assert decrypted == sample_plaintext

    def test_encrypt_decrypt_aes_gcm_with_associated_data(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Associated data is authenticated during decryption."""
        associated_data = b"additional authenticated data"
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(
            sample_plaintext, sample_aes_key, associated_data=associated_data
        )
        decrypted = decrypt_aes_gcm(
            nonce, ciphertext, auth_tag, sample_aes_key, associated_data=associated_data
        )
        assert decrypted == sample_plaintext

    def test_encrypt_decrypt_aes_gcm_wrong_key_raises_decryption_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Decryption with wrong key raises DecryptionError."""
        wrong_key = generate_aes_key()
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)

        with pytest.raises(DecryptionError):
            decrypt_aes_gcm(nonce, ciphertext, auth_tag, wrong_key)

    def test_encrypt_decrypt_aes_gcm_tampered_ciphertext_raises_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Tampered ciphertext raises DecryptionError."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        tampered_ciphertext = bytes([c ^ 0xFF for c in ciphertext])

        with pytest.raises(DecryptionError):
            decrypt_aes_gcm(nonce, tampered_ciphertext, auth_tag, sample_aes_key)

    def test_encrypt_decrypt_aes_gcm_tampered_auth_tag_raises_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Tampered auth tag raises DecryptionError."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        tampered_tag = bytes([t ^ 0xFF for t in auth_tag])

        with pytest.raises(DecryptionError):
            decrypt_aes_gcm(nonce, ciphertext, tampered_tag, sample_aes_key)

    def test_encrypt_decrypt_aes_gcm_wrong_nonce_raises_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Wrong nonce raises DecryptionError."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        wrong_nonce = generate_secure_random_bytes(AES_NONCE_SIZE)

        with pytest.raises(DecryptionError):
            decrypt_aes_gcm(wrong_nonce, ciphertext, auth_tag, sample_aes_key)

    def test_encrypt_aes_gcm_wrong_key_size_raises_value_error(
        self, sample_plaintext: bytes
    ) -> None:
        """Encryption with wrong key size raises ValueError."""
        wrong_key = b"short_key"
        with pytest.raises(ValueError, match="AES key must be"):
            encrypt_aes_gcm(sample_plaintext, wrong_key)

    def test_decrypt_aes_gcm_wrong_key_size_raises_value_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Decryption with wrong key size raises ValueError."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        wrong_key = b"short_key"

        with pytest.raises(ValueError, match="AES key must be"):
            decrypt_aes_gcm(nonce, ciphertext, auth_tag, wrong_key)

    def test_decrypt_aes_gcm_wrong_nonce_size_raises_value_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Decryption with wrong nonce size raises ValueError."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        wrong_nonce = b"short"

        with pytest.raises(ValueError, match="Nonce must be"):
            decrypt_aes_gcm(wrong_nonce, ciphertext, auth_tag, sample_aes_key)

    def test_decrypt_aes_gcm_wrong_tag_size_raises_value_error(
        self, sample_aes_key: bytes, sample_plaintext: bytes
    ) -> None:
        """Decryption with wrong tag size raises ValueError."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(sample_plaintext, sample_aes_key)
        wrong_tag = b"short_tag"

        with pytest.raises(ValueError, match="Auth tag must be"):
            decrypt_aes_gcm(nonce, ciphertext, wrong_tag, sample_aes_key)

    def test_encrypt_decrypt_aes_gcm_empty_plaintext(self, sample_aes_key: bytes) -> None:
        """Handles empty plaintext correctly."""
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(b"", sample_aes_key)
        decrypted = decrypt_aes_gcm(nonce, ciphertext, auth_tag, sample_aes_key)
        assert decrypted == b""

    def test_encrypt_decrypt_aes_gcm_large_data(
        self, sample_aes_key: bytes
    ) -> None:
        """Handles large data correctly."""
        large_data = generate_secure_random_bytes(1024 * 1024)
        nonce, ciphertext, auth_tag = encrypt_aes_gcm(large_data, sample_aes_key)
        decrypted = decrypt_aes_gcm(nonce, ciphertext, auth_tag, sample_aes_key)
        assert decrypted == large_data


class TestGenerateRsaKeypair:
    """Tests for RSA keypair generation."""

    def test_generate_rsa_keypair_default_size(self) -> None:
        """Generates keypair with default 2048-bit size."""
        private_key, public_key = generate_rsa_keypair()
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert private_key.key_size == 2048

    def test_generate_rsa_keypair_2048_bits(self) -> None:
        """Generates 2048-bit keypair."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        assert private_key.key_size == 2048

    def test_generate_rsa_keypair_4096_bits(self) -> None:
        """Generates 4096-bit keypair."""
        private_key, public_key = generate_rsa_keypair(key_size=4096)
        assert private_key.key_size == 4096

    def test_generate_rsa_keypair_too_small_raises_value_error(self) -> None:
        """Key size below 2048 raises ValueError."""
        with pytest.raises(ValueError, match="must be at least"):
            generate_rsa_keypair(key_size=1024)

    def test_generate_rsa_keypair_different_keys_each_call(self) -> None:
        """Generates different keys on each call."""
        priv1, pub1 = generate_rsa_keypair()
        priv2, pub2 = generate_rsa_keypair()
        assert priv1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ) != priv2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


from cryptography.hazmat.primitives import serialization


class TestSerializeDeserializeRsaKeys:
    """Tests for RSA key serialization and deserialization."""

    def test_serialize_deserialize_rsa_private_key(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Private key roundtrip serialization."""
        private_key, _ = rsa_keypair
        pem_data = serialize_rsa_private_key(private_key)
        restored_key = deserialize_rsa_private_key(pem_data)
        assert isinstance(restored_key, rsa.RSAPrivateKey)

    def test_serialize_deserialize_rsa_private_key_with_password(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey], sample_password: str
    ) -> None:
        """Password-encrypted private key roundtrip."""
        private_key, _ = rsa_keypair
        password = sample_password.encode("utf-8")
        pem_data = serialize_rsa_private_key(private_key, password=password)
        restored_key = deserialize_rsa_private_key(pem_data, password=password)
        assert isinstance(restored_key, rsa.RSAPrivateKey)

    def test_deserialize_rsa_private_key_wrong_password_raises_error(
        self,
        encrypted_rsa_private_key_pem: bytes,
        sample_password: str,
    ) -> None:
        """Wrong password raises CryptoError."""
        wrong_password = b"wrong_password"
        with pytest.raises(CryptoError):
            deserialize_rsa_private_key(encrypted_rsa_private_key_pem, password=wrong_password)

    def test_serialize_deserialize_rsa_public_key(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Public key roundtrip serialization."""
        _, public_key = rsa_keypair
        pem_data = serialize_rsa_public_key(public_key)
        restored_key = deserialize_rsa_public_key(pem_data)
        assert isinstance(restored_key, rsa.RSAPublicKey)


class TestRsaEncryptDecrypt:
    """Tests for RSA encryption and decryption."""

    def test_rsa_encrypt_decrypt_roundtrip(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Encryption followed by decryption returns original data."""
        private_key, public_key = rsa_keypair
        plaintext = b"Small data for RSA"
        ciphertext = rsa_encrypt(public_key, plaintext)
        decrypted = rsa_decrypt(private_key, ciphertext)
        assert decrypted == plaintext

    def test_rsa_encrypt_decrypt_empty_data(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Handles empty data correctly."""
        private_key, public_key = rsa_keypair
        ciphertext = rsa_encrypt(public_key, b"")
        decrypted = rsa_decrypt(private_key, ciphertext)
        assert decrypted == b""

    def test_rsa_decrypt_wrong_key_raises_decryption_error(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Decryption with different key raises DecryptionError."""
        private_key1, public_key1 = rsa_keypair
        private_key2, _ = generate_rsa_keypair()
        plaintext = b"test data"
        ciphertext = rsa_encrypt(public_key1, plaintext)

        with pytest.raises(DecryptionError):
            rsa_decrypt(private_key2, ciphertext)


class TestSignRsaVerifySignature:
    """Tests for RSA signing and signature verification."""

    def test_sign_rsa_verify_signature_valid(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Valid signature verifies successfully."""
        private_key, public_key = rsa_keypair
        data = b"Data to sign"
        signature = sign_rsa(private_key, data)
        is_valid = verify_rsa_signature(public_key, data, signature)
        assert is_valid is True

    def test_sign_rsa_verify_signature_tampered_data(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Tampered data fails signature verification."""
        private_key, public_key = rsa_keypair
        data = b"Original data"
        tampered_data = b"Tampered data"
        signature = sign_rsa(private_key, data)
        is_valid = verify_rsa_signature(public_key, tampered_data, signature)
        assert is_valid is False

    def test_sign_rsa_verify_signature_wrong_key(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Signature from different key fails verification."""
        private_key1, public_key1 = rsa_keypair
        _, public_key2 = generate_rsa_keypair()
        data = b"Data to sign"
        signature = sign_rsa(private_key1, data)
        is_valid = verify_rsa_signature(public_key2, data, signature)
        assert is_valid is False

    def test_sign_rsa_verify_signature_empty_data(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Empty data signs and verifies correctly."""
        private_key, public_key = rsa_keypair
        signature = sign_rsa(private_key, b"")
        is_valid = verify_rsa_signature(public_key, b"", signature)
        assert is_valid is True


class TestSha256Hash:
    """Tests for SHA-256 hashing functions."""

    def test_sha256_hash_returns_32_bytes(self) -> None:
        """Returns 32-byte hash."""
        result = sha256_hash(b"test data")
        assert len(result) == 32

    def test_sha256_hash_deterministic(self) -> None:
        """Same input produces same hash."""
        data = b"test data"
        hash1 = sha256_hash(data)
        hash2 = sha256_hash(data)
        assert hash1 == hash2

    def test_sha256_hash_different_inputs_different_hashes(self) -> None:
        """Different inputs produce different hashes."""
        hash1 = sha256_hash(b"data1")
        hash2 = sha256_hash(b"data2")
        assert hash1 != hash2

    def test_sha256_hash_empty_data(self) -> None:
        """Hashes empty data correctly."""
        result = sha256_hash(b"")
        assert len(result) == 32
        assert result == bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha256_hex_returns_64_character_string(self) -> None:
        """Returns 64-character hex string."""
        result = sha256_hex(b"test data")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_hex_matches_hash_digest(self) -> None:
        """Hex output matches hash digest in hex form."""
        data = b"test data"
        hash_bytes = sha256_hash(data)
        hash_hex = sha256_hex(data)
        assert hash_bytes.hex() == hash_hex


class TestHmacSha256:
    """Tests for HMAC-SHA256 operations."""

    def test_hmac_sha256_returns_32_bytes(self) -> None:
        """Returns 32-byte HMAC."""
        key = generate_secure_random_bytes(32)
        result = hmac_sha256(b"test data", key)
        assert len(result) == 32

    def test_hmac_sha256_deterministic(self) -> None:
        """Same input and key produce same HMAC."""
        key = generate_secure_random_bytes(32)
        data = b"test data"
        hmac1 = hmac_sha256(data, key)
        hmac2 = hmac_sha256(data, key)
        assert hmac1 == hmac2

    def test_hmac_sha256_different_keys_different_hmacs(self) -> None:
        """Different keys produce different HMACs."""
        data = b"test data"
        key1 = generate_secure_random_bytes(32)
        key2 = generate_secure_random_bytes(32)
        hmac1 = hmac_sha256(data, key1)
        hmac2 = hmac_sha256(data, key2)
        assert hmac1 != hmac2

    def test_verify_hmac_sha256_valid_signature(self) -> None:
        """Valid HMAC signature verifies successfully."""
        key = generate_secure_random_bytes(32)
        data = b"test data"
        signature = hmac_sha256(data, key)
        is_valid = verify_hmac_sha256(data, signature, key)
        assert is_valid is True

    def test_verify_hmac_sha256_invalid_signature(self) -> None:
        """Invalid HMAC signature fails verification."""
        key = generate_secure_random_bytes(32)
        data = b"test data"
        wrong_signature = generate_secure_random_bytes(32)
        is_valid = verify_hmac_sha256(data, wrong_signature, key)
        assert is_valid is False

    def test_verify_hmac_sha256_tampered_data(self) -> None:
        """Tampered data fails HMAC verification."""
        key = generate_secure_random_bytes(32)
        data = b"original data"
        tampered_data = b"tampered data"
        signature = hmac_sha256(data, key)
        is_valid = verify_hmac_sha256(tampered_data, signature, key)
        assert is_valid is False


class TestHashPasswordVerifyPassword:
    """Tests for bcrypt password hashing."""

    def test_hash_password_returns_60_character_string(
        self, sample_password: str
    ) -> None:
        """Returns 60-character bcrypt hash."""
        hash_result = hash_password(sample_password)
        assert len(hash_result) == 60

    def test_hash_password_different_salts_each_call(
        self, sample_password: str
    ) -> None:
        """Generates different salt on each call."""
        hash1 = hash_password(sample_password)
        hash2 = hash_password(sample_password)
        assert hash1 != hash2

    def test_hash_password_verify_password_valid(
        self, sample_password: str
    ) -> None:
        """Correct password verifies successfully."""
        password_hash = hash_password(sample_password)
        is_valid = verify_password(sample_password, password_hash)
        assert is_valid is True

    def test_hash_password_verify_password_invalid(
        self, sample_password: str
    ) -> None:
        """Wrong password fails verification."""
        password_hash = hash_password(sample_password)
        is_valid = verify_password("wrong_password", password_hash)
        assert is_valid is False

    def test_hash_password_verify_password_unicode(
        self,
    ) -> None:
        """Handles unicode passwords correctly."""
        password = "Pässwörd123!ñ"
        password_hash = hash_password(password)
        is_valid = verify_password(password, password_hash)
        assert is_valid is True

    def test_hash_password_custom_rounds(self, sample_password: str) -> None:
        """Accepts custom rounds parameter."""
        hash_result = hash_password(sample_password, rounds=10)
        assert len(hash_result) == 60
        assert hash_result.startswith("$2b$10$")

    def test_hash_password_rounds_too_low_raises_value_error(
        self, sample_password: str
    ) -> None:
        """Rounds below 10 raises ValueError."""
        with pytest.raises(ValueError, match="must be between"):
            hash_password(sample_password, rounds=5)

    def test_hash_password_rounds_too_high_raises_value_error(
        self, sample_password: str
    ) -> None:
        """Rounds above 31 raises ValueError."""
        with pytest.raises(ValueError, match="must be between"):
            hash_password(sample_password, rounds=32)


class TestTimingSafeCompare:
    """Tests for constant-time comparison functions."""

    def test_timing_safe_compare_equal_bytes(self) -> None:
        """Returns True for equal byte strings."""
        data = b"test data"
        assert timing_safe_compare(data, data) is True

    def test_timing_safe_compare_unequal_bytes(self) -> None:
        """Returns False for unequal byte strings."""
        assert timing_safe_compare(b"data1", b"data2") is False

    def test_timing_safe_compare_different_length_bytes(self) -> None:
        """Returns False for different length byte strings."""
        assert timing_safe_compare(b"short", b"much longer data") is False

    def test_timing_safe_compare_empty_bytes(self) -> None:
        """Handles empty byte strings correctly."""
        assert timing_safe_compare(b"", b"") is True
        assert timing_safe_compare(b"", b"data") is False

    def test_timing_safe_compare_str_equal_strings(self) -> None:
        """Returns True for equal strings."""
        data = "test string"
        assert timing_safe_compare_str(data, data) is True

    def test_timing_safe_compare_str_unequal_strings(self) -> None:
        """Returns False for unequal strings."""
        assert timing_safe_compare_str("string1", "string2") is False

    def test_timing_safe_compare_str_unicode_strings(self) -> None:
        """Handles unicode strings correctly."""
        str1 = "Pässwörd"
        str2 = "Pässwörd"
        str3 = "Different"
        assert timing_safe_compare_str(str1, str2) is True
        assert timing_safe_compare_str(str1, str3) is False


class TestDeriveKeyFromPassword:
    """Tests for PBKDF2 key derivation."""

    def test_derive_key_from_password_returns_32_bytes(
        self, sample_password: str
    ) -> None:
        """Returns 32-byte derived key."""
        salt = generate_secure_random_bytes(16)
        key = derive_key_from_password(sample_password, salt)
        assert len(key) == 32

    def test_derive_key_from_password_deterministic(
        self, sample_password: str
    ) -> None:
        """Same password and salt produce same key."""
        salt = generate_secure_random_bytes(16)
        key1 = derive_key_from_password(sample_password, salt)
        key2 = derive_key_from_password(sample_password, salt)
        assert key1 == key2

    def test_derive_key_from_password_different_salts_different_keys(
        self, sample_password: str
    ) -> None:
        """Different salts produce different keys."""
        salt1 = generate_secure_random_bytes(16)
        salt2 = generate_secure_random_bytes(16)
        key1 = derive_key_from_password(sample_password, salt1)
        key2 = derive_key_from_password(sample_password, salt2)
        assert key1 != key2

    def test_derive_key_from_password_custom_iterations(
        self, sample_password: str
    ) -> None:
        """Accepts custom iterations parameter."""
        salt = generate_secure_random_bytes(16)
        key = derive_key_from_password(sample_password, salt, iterations=50000)
        assert len(key) == 32
