"""
Security Core Exceptions

Custom exception classes for security operations including
cryptography, Vault integration, JWT handling, and utilities.
"""


class SecurityError(Exception):
    """Base exception for all security-related errors."""

    pass


class CryptoError(SecurityError):
    """Base exception for cryptographic operations."""

    pass


class EncryptionError(CryptoError):
    """Raised when encryption operation fails."""

    pass


class DecryptionError(CryptoError):
    """Raised when decryption operation fails."""

    pass


class KeyGenerationError(CryptoError):
    """Raised when cryptographic key generation fails."""

    pass


class HashError(CryptoError):
    """Raised when hashing operation fails."""

    pass


class SignatureError(CryptoError):
    """Raised when digital signature operation fails."""

    pass


class VaultError(SecurityError):
    """Base exception for HashiCorp Vault operations."""

    pass


class VaultConnectionError(VaultError):
    """Raised when Vault connection fails."""

    pass


class VaultAuthenticationError(VaultError):
    """Raised when Vault authentication fails."""

    pass


class VaultSecretNotFoundError(VaultError):
    """Raised when requested secret is not found in Vault."""

    pass


class VaultPermissionError(VaultError):
    """Raised when Vault operation lacks sufficient permissions."""

    pass


class VaultLeaseError(VaultError):
    """Raised when Vault lease operation fails."""

    pass


class JWTError(SecurityError):
    """Base exception for JWT operations."""

    pass


class JWTDecodeError(JWTError):
    """Raised when JWT decoding fails."""

    pass


class JWTExpiredError(JWTError):
    """Raised when JWT token has expired."""

    pass


class JWTInvalidClaimsError(JWTError):
    """Raised when JWT claims are invalid or missing."""

    pass


class JWTRevokedError(JWTError):
    """Raised when JWT token has been revoked."""

    pass


class SecurityValidationError(SecurityError):
    """Raised when security validation fails."""

    pass


class SecurityInitializationError(SecurityError):
    """Raised when security component initialization fails."""

    pass
