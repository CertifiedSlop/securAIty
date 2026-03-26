"""
Unit tests for security exception hierarchy in securAIty security module.

Tests verify exception inheritance, proper messages, and exception chaining.
"""

import pytest

from securAIty.security.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    HashError,
    JWTDecodeError,
    JWTError,
    JWTExpiredError,
    JWTInvalidClaimsError,
    JWTRevokedError,
    KeyGenerationError,
    SecurityError,
    SecurityInitializationError,
    SecurityValidationError,
    SignatureError,
    VaultAuthenticationError,
    VaultConnectionError,
    VaultError,
    VaultLeaseError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


class TestSecurityExceptionHierarchy:
    """Tests for security exception inheritance hierarchy."""

    def test_security_error_is_base_exception(self) -> None:
        """SecurityError is the base exception for all security errors."""
        assert issubclass(SecurityError, Exception)

    def test_crypto_error_inherits_from_security_error(self) -> None:
        """CryptoError inherits from SecurityError."""
        assert issubclass(CryptoError, SecurityError)

    def test_encryption_error_inherits_from_crypto_error(self) -> None:
        """EncryptionError inherits from CryptoError."""
        assert issubclass(EncryptionError, CryptoError)

    def test_encryption_error_inherits_from_security_error(self) -> None:
        """EncryptionError inherits from SecurityError through CryptoError."""
        assert issubclass(EncryptionError, SecurityError)

    def test_decryption_error_inherits_from_crypto_error(self) -> None:
        """DecryptionError inherits from CryptoError."""
        assert issubclass(DecryptionError, CryptoError)

    def test_decryption_error_inherits_from_security_error(self) -> None:
        """DecryptionError inherits from SecurityError through CryptoError."""
        assert issubclass(DecryptionError, SecurityError)

    def test_key_generation_error_inherits_from_crypto_error(self) -> None:
        """KeyGenerationError inherits from CryptoError."""
        assert issubclass(KeyGenerationError, CryptoError)

    def test_key_generation_error_inherits_from_security_error(self) -> None:
        """KeyGenerationError inherits from SecurityError through CryptoError."""
        assert issubclass(KeyGenerationError, SecurityError)

    def test_hash_error_inherits_from_crypto_error(self) -> None:
        """HashError inherits from CryptoError."""
        assert issubclass(HashError, CryptoError)

    def test_hash_error_inherits_from_security_error(self) -> None:
        """HashError inherits from SecurityError through CryptoError."""
        assert issubclass(HashError, SecurityError)

    def test_signature_error_inherits_from_crypto_error(self) -> None:
        """SignatureError inherits from CryptoError."""
        assert issubclass(SignatureError, CryptoError)

    def test_signature_error_inherits_from_security_error(self) -> None:
        """SignatureError inherits from SecurityError through CryptoError."""
        assert issubclass(SignatureError, SecurityError)

    def test_vault_error_inherits_from_security_error(self) -> None:
        """VaultError inherits from SecurityError."""
        assert issubclass(VaultError, SecurityError)

    def test_vault_connection_error_inherits_from_vault_error(self) -> None:
        """VaultConnectionError inherits from VaultError."""
        assert issubclass(VaultConnectionError, VaultError)

    def test_vault_connection_error_inherits_from_security_error(self) -> None:
        """VaultConnectionError inherits from SecurityError through VaultError."""
        assert issubclass(VaultConnectionError, SecurityError)

    def test_vault_authentication_error_inherits_from_vault_error(self) -> None:
        """VaultAuthenticationError inherits from VaultError."""
        assert issubclass(VaultAuthenticationError, VaultError)

    def test_vault_authentication_error_inherits_from_security_error(self) -> None:
        """VaultAuthenticationError inherits from SecurityError through VaultError."""
        assert issubclass(VaultAuthenticationError, SecurityError)

    def test_vault_secret_not_found_error_inherits_from_vault_error(self) -> None:
        """VaultSecretNotFoundError inherits from VaultError."""
        assert issubclass(VaultSecretNotFoundError, VaultError)

    def test_vault_secret_not_found_error_inherits_from_security_error(self) -> None:
        """VaultSecretNotFoundError inherits from SecurityError through VaultError."""
        assert issubclass(VaultSecretNotFoundError, SecurityError)

    def test_vault_permission_error_inherits_from_vault_error(self) -> None:
        """VaultPermissionError inherits from VaultError."""
        assert issubclass(VaultPermissionError, VaultError)

    def test_vault_permission_error_inherits_from_security_error(self) -> None:
        """VaultPermissionError inherits from SecurityError through VaultError."""
        assert issubclass(VaultPermissionError, SecurityError)

    def test_vault_lease_error_inherits_from_vault_error(self) -> None:
        """VaultLeaseError inherits from VaultError."""
        assert issubclass(VaultLeaseError, VaultError)

    def test_vault_lease_error_inherits_from_security_error(self) -> None:
        """VaultLeaseError inherits from SecurityError through VaultError."""
        assert issubclass(VaultLeaseError, SecurityError)

    def test_jwt_error_inherits_from_security_error(self) -> None:
        """JWTError inherits from SecurityError."""
        assert issubclass(JWTError, SecurityError)

    def test_jwt_decode_error_inherits_from_jwt_error(self) -> None:
        """JWTDecodeError inherits from JWTError."""
        assert issubclass(JWTDecodeError, JWTError)

    def test_jwt_decode_error_inherits_from_security_error(self) -> None:
        """JWTDecodeError inherits from SecurityError through JWTError."""
        assert issubclass(JWTDecodeError, SecurityError)

    def test_jwt_expired_error_inherits_from_jwt_error(self) -> None:
        """JWTExpiredError inherits from JWTError."""
        assert issubclass(JWTExpiredError, JWTError)

    def test_jwt_expired_error_inherits_from_security_error(self) -> None:
        """JWTExpiredError inherits from SecurityError through JWTError."""
        assert issubclass(JWTExpiredError, SecurityError)

    def test_jwt_invalid_claims_error_inherits_from_jwt_error(self) -> None:
        """JWTInvalidClaimsError inherits from JWTError."""
        assert issubclass(JWTInvalidClaimsError, JWTError)

    def test_jwt_invalid_claims_error_inherits_from_security_error(self) -> None:
        """JWTInvalidClaimsError inherits from SecurityError through JWTError."""
        assert issubclass(JWTInvalidClaimsError, SecurityError)

    def test_jwt_revoked_error_inherits_from_jwt_error(self) -> None:
        """JWTRevokedError inherits from JWTError."""
        assert issubclass(JWTRevokedError, JWTError)

    def test_jwt_revoked_error_inherits_from_security_error(self) -> None:
        """JWTRevokedError inherits from SecurityError through JWTError."""
        assert issubclass(JWTRevokedError, SecurityError)

    def test_security_validation_error_inherits_from_security_error(self) -> None:
        """SecurityValidationError inherits from SecurityError."""
        assert issubclass(SecurityValidationError, SecurityError)

    def test_security_initialization_error_inherits_from_security_error(self) -> None:
        """SecurityInitializationError inherits from SecurityError."""
        assert issubclass(SecurityInitializationError, SecurityError)


class TestSecurityExceptionMessages:
    """Tests for security exception message handling."""

    def test_security_error_with_message(self) -> None:
        """SecurityError stores custom message."""
        error = SecurityError("Custom error message")
        assert str(error) == "Custom error message"

    def test_security_error_without_message(self) -> None:
        """SecurityError handles empty message."""
        error = SecurityError()
        assert str(error) == ""

    def test_crypto_error_with_message(self) -> None:
        """CryptoError stores custom message."""
        error = CryptoError("Crypto operation failed")
        assert str(error) == "Crypto operation failed"

    def test_encryption_error_with_message(self) -> None:
        """EncryptionError stores custom message."""
        error = EncryptionError("AES encryption failed")
        assert str(error) == "AES encryption failed"

    def test_decryption_error_with_message(self) -> None:
        """DecryptionError stores custom message."""
        error = DecryptionError("Invalid key provided")
        assert str(error) == "Invalid key provided"

    def test_key_generation_error_with_message(self) -> None:
        """KeyGenerationError stores custom message."""
        error = KeyGenerationError("Failed to generate key")
        assert str(error) == "Failed to generate key"

    def test_hash_error_with_message(self) -> None:
        """HashError stores custom message."""
        error = HashError("Hashing operation failed")
        assert str(error) == "Hashing operation failed"

    def test_signature_error_with_message(self) -> None:
        """SignatureError stores custom message."""
        error = SignatureError("Signature verification failed")
        assert str(error) == "Signature verification failed"

    def test_vault_error_with_message(self) -> None:
        """VaultError stores custom message."""
        error = VaultError("Vault operation failed")
        assert str(error) == "Vault operation failed"

    def test_vault_connection_error_with_message(self) -> None:
        """VaultConnectionError stores custom message."""
        error = VaultConnectionError("Cannot connect to Vault")
        assert str(error) == "Cannot connect to Vault"

    def test_vault_authentication_error_with_message(self) -> None:
        """VaultAuthenticationError stores custom message."""
        error = VaultAuthenticationError("Authentication failed")
        assert str(error) == "Authentication failed"

    def test_vault_secret_not_found_error_with_message(self) -> None:
        """VaultSecretNotFoundError stores custom message."""
        error = VaultSecretNotFoundError("Secret not found at path")
        assert str(error) == "Secret not found at path"

    def test_vault_permission_error_with_message(self) -> None:
        """VaultPermissionError stores custom message."""
        error = VaultPermissionError("Permission denied")
        assert str(error) == "Permission denied"

    def test_vault_lease_error_with_message(self) -> None:
        """VaultLeaseError stores custom message."""
        error = VaultLeaseError("Lease operation failed")
        assert str(error) == "Lease operation failed"

    def test_jwt_error_with_message(self) -> None:
        """JWTError stores custom message."""
        error = JWTError("JWT operation failed")
        assert str(error) == "JWT operation failed"

    def test_jwt_decode_error_with_message(self) -> None:
        """JWTDecodeError stores custom message."""
        error = JWTDecodeError("Invalid token format")
        assert str(error) == "Invalid token format"

    def test_jwt_expired_error_with_message(self) -> None:
        """JWTExpiredError stores custom message."""
        error = JWTExpiredError("Token has expired")
        assert str(error) == "Token has expired"

    def test_jwt_invalid_claims_error_with_message(self) -> None:
        """JWTInvalidClaimsError stores custom message."""
        error = JWTInvalidClaimsError("Missing required claims")
        assert str(error) == "Missing required claims"

    def test_jwt_revoked_error_with_message(self) -> None:
        """JWTRevokedError stores custom message."""
        error = JWTRevokedError("Token has been revoked")
        assert str(error) == "Token has been revoked"

    def test_security_validation_error_with_message(self) -> None:
        """SecurityValidationError stores custom message."""
        error = SecurityValidationError("Validation failed")
        assert str(error) == "Validation failed"

    def test_security_initialization_error_with_message(self) -> None:
        """SecurityInitializationError stores custom message."""
        error = SecurityInitializationError("Initialization failed")
        assert str(error) == "Initialization failed"


class TestSecurityExceptionChaining:
    """Tests for security exception chaining."""

    def test_crypto_error_with_cause(self) -> None:
        """CryptoError preserves exception cause."""
        original_error = ValueError("Original error")
        try:
            raise original_error
        except ValueError:
            try:
                raise CryptoError("Crypto operation failed") from original_error
            except CryptoError as crypto_error:
                assert crypto_error.__cause__ is original_error

    def test_encryption_error_with_cause(self) -> None:
        """EncryptionError preserves exception cause."""
        original_error = Exception("Encryption backend error")
        try:
            raise original_error
        except Exception:
            try:
                raise EncryptionError("AES encryption failed") from original_error
            except EncryptionError as enc_error:
                assert enc_error.__cause__ is original_error

    def test_decryption_error_with_cause(self) -> None:
        """DecryptionError preserves exception cause."""
        original_error = Exception("Invalid ciphertext")
        try:
            raise original_error
        except Exception:
            try:
                raise DecryptionError("Decryption failed") from original_error
            except DecryptionError as dec_error:
                assert dec_error.__cause__ is original_error

    def test_vault_connection_error_with_cause(self) -> None:
        """VaultConnectionError preserves exception cause."""
        original_error = ConnectionError("Connection refused")
        try:
            raise original_error
        except ConnectionError:
            try:
                raise VaultConnectionError("Vault unreachable") from original_error
            except VaultConnectionError as vault_error:
                assert vault_error.__cause__ is original_error

    def test_vault_authentication_error_with_cause(self) -> None:
        """VaultAuthenticationError preserves exception cause."""
        original_error = PermissionError("Invalid credentials")
        try:
            raise original_error
        except PermissionError:
            try:
                raise VaultAuthenticationError("Auth failed") from original_error
            except VaultAuthenticationError as auth_error:
                assert auth_error.__cause__ is original_error

    def test_jwt_decode_error_with_cause(self) -> None:
        """JWTDecodeError preserves exception cause."""
        original_error = Exception("Invalid base64")
        try:
            raise original_error
        except Exception:
            try:
                raise JWTDecodeError("Token decode failed") from original_error
            except JWTDecodeError as jwt_error:
                assert jwt_error.__cause__ is original_error


class TestSecurityExceptionCatching:
    """Tests for catching security exceptions by base class."""

    def test_catch_crypto_error_subclasses_as_crypto_error(self) -> None:
        """Can catch CryptoError subclasses as CryptoError."""
        exceptions_caught = []

        for exc_class in [
            EncryptionError,
            DecryptionError,
            KeyGenerationError,
            HashError,
            SignatureError,
        ]:
            try:
                raise exc_class(f"Test {exc_class.__name__}")
            except CryptoError as e:
                exceptions_caught.append(type(e))

        assert len(exceptions_caught) == 5
        assert all(issubclass(exc, CryptoError) for exc in exceptions_caught)

    def test_catch_vault_error_subclasses_as_vault_error(self) -> None:
        """Can catch VaultError subclasses as VaultError."""
        exceptions_caught = []

        for exc_class in [
            VaultConnectionError,
            VaultAuthenticationError,
            VaultSecretNotFoundError,
            VaultPermissionError,
            VaultLeaseError,
        ]:
            try:
                raise exc_class(f"Test {exc_class.__name__}")
            except VaultError as e:
                exceptions_caught.append(type(e))

        assert len(exceptions_caught) == 5
        assert all(issubclass(exc, VaultError) for exc in exceptions_caught)

    def test_catch_jwt_error_subclasses_as_jwt_error(self) -> None:
        """Can catch JWTError subclasses as JWTError."""
        exceptions_caught = []

        for exc_class in [
            JWTDecodeError,
            JWTExpiredError,
            JWTInvalidClaimsError,
            JWTRevokedError,
        ]:
            try:
                raise exc_class(f"Test {exc_class.__name__}")
            except JWTError as e:
                exceptions_caught.append(type(e))

        assert len(exceptions_caught) == 4
        assert all(issubclass(exc, JWTError) for exc in exceptions_caught)

    def test_catch_all_security_errors_as_security_error(self) -> None:
        """Can catch all security errors as SecurityError."""
        all_error_classes = [
            CryptoError,
            EncryptionError,
            DecryptionError,
            KeyGenerationError,
            HashError,
            SignatureError,
            VaultError,
            VaultConnectionError,
            VaultAuthenticationError,
            VaultSecretNotFoundError,
            VaultPermissionError,
            VaultLeaseError,
            JWTError,
            JWTDecodeError,
            JWTExpiredError,
            JWTInvalidClaimsError,
            JWTRevokedError,
            SecurityValidationError,
            SecurityInitializationError,
        ]

        exceptions_caught = []

        for exc_class in all_error_classes:
            try:
                raise exc_class(f"Test {exc_class.__name__}")
            except SecurityError as e:
                exceptions_caught.append(type(e))

        assert len(exceptions_caught) == len(all_error_classes)
        assert all(issubclass(exc, SecurityError) for exc in exceptions_caught)


class TestSecurityExceptionAttributes:
    """Tests for security exception attributes."""

    def test_security_error_args_attribute(self) -> None:
        """SecurityError stores args tuple."""
        error = SecurityError("message", "extra", "data")
        assert error.args == ("message", "extra", "data")

    def test_crypto_error_args_attribute(self) -> None:
        """CryptoError stores args tuple."""
        error = CryptoError("crypto error")
        assert error.args == ("crypto error",)

    def test_exception_with_multiple_args(self) -> None:
        """Exception with multiple args stores all."""
        error = VaultError("error", {"key": "value"}, 123)
        assert len(error.args) == 3
        assert error.args[0] == "error"
        assert error.args[1] == {"key": "value"}
        assert error.args[2] == 123


class TestSecurityExceptionTraceback:
    """Tests for security exception traceback preservation."""

    def test_exception_traceback_preserved(self) -> None:
        """Exception traceback is preserved when raising."""
        import traceback

        try:
            raise EncryptionError("Test error")
        except EncryptionError as e:
            tb_str = traceback.format_exception(type(e), e, e.__traceback__)
            assert "EncryptionError" in "".join(tb_str)
            assert "Test error" in "".join(tb_str)

    def test_chained_exception_traceback(self) -> None:
        """Chained exception shows both exceptions."""
        import traceback

        original_error = ValueError("Original error")
        try:
            raise EncryptionError("Crypto error") from original_error
        except EncryptionError as e:
            tb_str = traceback.format_exception(type(e), e, e.__traceback__)
            tb_text = "".join(tb_str)
            assert "EncryptionError" in tb_text
            assert "Crypto error" in tb_text
            assert "ValueError" in tb_text
            assert "Original error" in tb_text
