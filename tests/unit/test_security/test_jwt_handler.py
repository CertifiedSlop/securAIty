"""
Unit tests for JWT handler in securAIty security module.

Tests cover token generation, validation, revocation, refresh,
and error handling for JWT operations.
"""

import asyncio
import time
from datetime import timedelta
from typing import Optional
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from securAIty.security.exceptions import (
    JWTDecodeError,
    JWTExpiredError,
    JWTInvalidClaimsError,
    JWTRevokedError,
)
from securAIty.security.jwt_handler import (
    DEFAULT_ACCESS_TOKEN_LIFETIME,
    DEFAULT_REFRESH_TOKEN_LIFETIME,
    JWTHandler,
    TokenClaims,
    TokenPair,
    TokenRevocationStore,
)


class TestTokenClaims:
    """Tests for TokenClaims dataclass."""

    def test_token_claims_to_dict_minimal(self) -> None:
        """Converts minimal claims to dictionary."""
        claims = TokenClaims(user_id="user-123")
        result = claims.to_dict()

        assert result["sub"] == "user-123"
        assert result["type"] == "access"
        assert "roles" not in result or result.get("roles") == []
        assert "permissions" not in result or result.get("permissions") == []

    def test_token_claims_to_dict_full(self) -> None:
        """Converts full claims to dictionary."""
        claims = TokenClaims(
            user_id="user-123",
            roles=["admin", "user"],
            permissions=["read", "write"],
            session_id="session-456",
            jti="jti-789",
            exp=1234567890,
            iat=1234567800,
            nbf=1234567800,
            iss="test-issuer",
            aud="test-audience",
            scope="read:users",
            type="access",
        )
        result = claims.to_dict()

        assert result["sub"] == "user-123"
        assert result["roles"] == ["admin", "user"]
        assert result["permissions"] == ["read", "write"]
        assert result["session_id"] == "session-456"
        assert result["jti"] == "jti-789"
        assert result["exp"] == 1234567890
        assert result["iat"] == 1234567800
        assert result["nbf"] == 1234567800
        assert result["iss"] == "test-issuer"
        assert result["aud"] == "test-audience"
        assert result["scope"] == "read:users"
        assert result["type"] == "access"

    def test_token_claims_from_dict_minimal(self) -> None:
        """Creates claims from minimal dictionary."""
        data = {"sub": "user-123", "type": "access"}
        claims = TokenClaims.from_dict(data)

        assert claims.user_id == "user-123"
        assert claims.type == "access"
        assert claims.roles == []
        assert claims.permissions == []

    def test_token_claims_from_dict_full(self) -> None:
        """Creates claims from full dictionary."""
        data = {
            "sub": "user-123",
            "roles": ["admin"],
            "permissions": ["read"],
            "session_id": "session-456",
            "jti": "jti-789",
            "exp": 1234567890,
            "iat": 1234567800,
            "nbf": 1234567800,
            "iss": "test-issuer",
            "aud": "test-audience",
            "scope": "read:users",
            "type": "refresh",
        }
        claims = TokenClaims.from_dict(data)

        assert claims.user_id == "user-123"
        assert claims.roles == ["admin"]
        assert claims.permissions == ["read"]
        assert claims.session_id == "session-456"
        assert claims.jti == "jti-789"
        assert claims.exp == 1234567890
        assert claims.type == "refresh"

    def test_token_claims_is_expired_true(self) -> None:
        """Returns True when token is expired."""
        claims = TokenClaims(user_id="user-123", exp=int(time.time()) - 100)
        assert claims.is_expired is True

    def test_token_claims_is_expired_false(self) -> None:
        """Returns False when token is not expired."""
        claims = TokenClaims(user_id="user-123", exp=int(time.time()) + 3600)
        assert claims.is_expired is False

    def test_token_claims_is_expired_no_exp(self) -> None:
        """Returns False when no expiration set."""
        claims = TokenClaims(user_id="user-123")
        assert claims.is_expired is False

    def test_token_claims_is_not_yet_valid_true(self) -> None:
        """Returns True when token is not yet valid."""
        claims = TokenClaims(user_id="user-123", nbf=int(time.time()) + 3600)
        assert claims.is_not_yet_valid is True

    def test_token_claims_is_not_yet_valid_false(self) -> None:
        """Returns False when token is valid."""
        claims = TokenClaims(user_id="user-123", nbf=int(time.time()) - 100)
        assert claims.is_not_yet_valid is False

    def test_token_claims_is_not_yet_valid_no_nbf(self) -> None:
        """Returns False when no nbf set."""
        claims = TokenClaims(user_id="user-123")
        assert claims.is_not_yet_valid is False


class TestTokenPair:
    """Tests for TokenPair dataclass."""

    def test_token_pair_to_dict(self) -> None:
        """Converts token pair to dictionary."""
        pair = TokenPair(
            access_token="access_token_value",
            refresh_token="refresh_token_value",
            token_type="Bearer",
            expires_in=900,
            refresh_expires_in=604800,
        )
        result = pair.to_dict()

        assert result["access_token"] == "access_token_value"
        assert result["refresh_token"] == "refresh_token_value"
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 900
        assert result["refresh_expires_in"] == 604800

    def test_token_pair_default_values(self) -> None:
        """Uses default values for optional fields."""
        pair = TokenPair(access_token="access", refresh_token="refresh")

        assert pair.token_type == "Bearer"
        assert pair.expires_in == 900
        assert pair.refresh_expires_in == 604800


class TestTokenRevocationStore:
    """Tests for TokenRevocationStore class."""

    @pytest.mark.asyncio
    async def test_token_revocation_store_add_and_is_revoked(self) -> None:
        """Added tokens are marked as revoked."""
        store = TokenRevocationStore()
        await store.start()
        try:
            await store.add("jti-123", "user-123", exp=int(time.time()) + 3600)
            is_revoked = await store.is_revoked("jti-123")
            assert is_revoked is True
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_token_revocation_store_not_revoked(self) -> None:
        """Non-added tokens are not marked as revoked."""
        store = TokenRevocationStore()
        await store.start()
        try:
            is_revoked = await store.is_revoked("jti-nonexistent")
            assert is_revoked is False
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_token_revocation_store_revoke_user_tokens(self) -> None:
        """Revokes all tokens for a user."""
        store = TokenRevocationStore()
        await store.start()
        try:
            await store.add("jti-1", "user-123", exp=int(time.time()) + 3600)
            await store.add("jti-2", "user-123", exp=int(time.time()) + 3600)
            await store.add("jti-3", "user-456", exp=int(time.time()) + 3600)

            count = await store.revoke_user_tokens("user-123")
            assert count == 2

            assert await store.is_revoked("jti-1") is True
            assert await store.is_revoked("jti-2") is True
            assert await store.is_revoked("jti-3") is False
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_token_revocation_store_revoke_nonexistent_user(self) -> None:
        """Returns 0 for non-existent user."""
        store = TokenRevocationStore()
        await store.start()
        try:
            count = await store.revoke_user_tokens("nonexistent-user")
            assert count == 0
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_token_revocation_store_get_revoked_count(self) -> None:
        """Returns correct count of revoked tokens."""
        store = TokenRevocationStore()
        await store.start()
        try:
            await store.add("jti-1", "user-123")
            await store.add("jti-2", "user-123")
            await store.add("jti-3", "user-456")

            count = await store.get_revoked_count()
            assert count == 3
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_token_revocation_store_clear(self) -> None:
        """Clears all revoked tokens."""
        store = TokenRevocationStore()
        await store.start()
        try:
            await store.add("jti-1", "user-123")
            await store.add("jti-2", "user-123")

            await store.clear()

            count = await store.get_revoked_count()
            assert count == 0
        finally:
            await store.stop()

    @pytest.mark.asyncio
    async def test_token_revocation_store_cleanup_expired(self) -> None:
        """Cleans up expired tokens."""
        store = TokenRevocationStore()
        await store.start()
        try:
            expired_jti = "jti-expired"
            expired_exp = int(time.time()) - 100
            await store.add(expired_jti, "user-123", exp=expired_exp)

            await store._cleanup_expired()

            is_revoked = await store.is_revoked(expired_jti)
            assert is_revoked is False
        finally:
            await store.stop()


class TestJWTHandlerInitialization:
    """Tests for JWTHandler initialization."""

    def test_jwt_handler_initialization_with_generated_keys(self) -> None:
        """Initializes with auto-generated keys."""
        handler = JWTHandler()

        assert handler._private_key is not None
        assert handler._public_key is not None
        assert handler._issuer == "securAIty"
        assert handler._audience == "securAIty-api"

    def test_jwt_handler_initialization_with_provided_keys(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Initializes with provided keys."""
        private_key, public_key = rsa_keypair
        handler = JWTHandler(private_key=private_key, public_key=public_key)

        assert handler._private_key == private_key
        assert handler._public_key == public_key

    def test_jwt_handler_initialization_custom_issuer_audience(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Initializes with custom issuer and audience."""
        private_key, public_key = rsa_keypair
        handler = JWTHandler(
            private_key=private_key,
            public_key=public_key,
            issuer="custom-issuer",
            audience="custom-audience",
        )

        assert handler._issuer == "custom-issuer"
        assert handler._audience == "custom-audience"

    def test_jwt_handler_from_keys_with_pem(
        self,
        rsa_private_key_pem: bytes,
        rsa_public_key_pem: bytes,
    ) -> None:
        """Initializes from PEM-encoded keys."""
        handler = JWTHandler.from_keys(
            private_key_pem=rsa_private_key_pem,
            public_key_pem=rsa_public_key_pem,
        )

        assert handler._private_key is not None
        assert handler._public_key is not None

    def test_jwt_handler_from_keys_with_encrypted_private_key(
        self,
        encrypted_rsa_private_key_pem: bytes,
        rsa_public_key_pem: bytes,
        sample_password: str,
    ) -> None:
        """Initializes from encrypted PEM-encoded keys."""
        handler = JWTHandler.from_keys(
            private_key_pem=encrypted_rsa_private_key_pem,
            public_key_pem=rsa_public_key_pem,
            password=sample_password.encode("utf-8"),
        )

        assert handler._private_key is not None
        assert handler._public_key is not None

    def test_jwt_handler_from_keys_wrong_key_type_raises_error(
        self, rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
    ) -> None:
        """Raises JWTError for non-RSA keys."""
        private_key, _ = rsa_keypair
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with pytest.raises(Exception, match="must be RSA"):
            JWTHandler.from_keys(private_key_pem=pem_data)


class TestJWTHandlerCreateAccessToken:
    """Tests for JWTHandler create_access_token method."""

    def test_create_access_token_returns_string(self) -> None:
        """Returns a string token."""
        handler = JWTHandler()
        token = handler.create_access_token(user_id="user-123")

        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_access_token_correct_claims_with_15_min_expiry(self) -> None:
        """Creates token with correct claims and 15 minute expiry."""
        handler = JWTHandler()
        token = handler.create_access_token(user_id="user-123")

        claims = handler.decode_token(token)

        assert claims.user_id == "user-123"
        assert claims.type == "access"
        assert claims.iss == "securAIty"
        assert claims.aud == "securAIty-api"
        assert claims.exp is not None
        assert claims.iat is not None
        assert claims.exp - claims.iat == 900

    def test_create_access_token_with_roles_permissions(
        self,
    ) -> None:
        """Creates token with roles and permissions."""
        handler = JWTHandler()
        token = handler.create_access_token(
            user_id="user-123",
            roles=["admin", "user"],
            permissions=["read", "write"],
        )

        claims = handler.decode_token(token)

        assert claims.roles == ["admin", "user"]
        assert claims.permissions == ["read", "write"]

    def test_create_access_token_with_session_id(self) -> None:
        """Creates token with session ID."""
        handler = JWTHandler()
        token = handler.create_access_token(
            user_id="user-123", session_id="session-456"
        )

        claims = handler.decode_token(token)

        assert claims.session_id == "session-456"

    def test_create_access_token_with_custom_lifetime(self) -> None:
        """Creates token with custom lifetime."""
        handler = JWTHandler()
        custom_lifetime = timedelta(hours=2)
        token = handler.create_access_token(
            user_id="user-123", lifetime=custom_lifetime
        )

        claims = handler.decode_token(token)

        assert claims.exp is not None
        assert claims.iat is not None
        assert claims.exp - claims.iat == 7200

    def test_create_access_token_with_scope(self) -> None:
        """Creates token with scope."""
        handler = JWTHandler()
        token = handler.create_access_token(
            user_id="user-123", scope="read:users write:users"
        )

        claims = handler.decode_token(token)

        assert claims.scope == "read:users write:users"

    def test_create_access_token_unique_jti_each_call(self) -> None:
        """Generates unique JTI for each token."""
        handler = JWTHandler()
        token1 = handler.create_access_token(user_id="user-123")
        token2 = handler.create_access_token(user_id="user-123")

        claims1 = handler.decode_token(token1)
        claims2 = handler.decode_token(token2)

        assert claims1.jti != claims2.jti


class TestJWTHandlerCreateRefreshToken:
    """Tests for JWTHandler create_refresh_token method."""

    def test_create_refresh_token_returns_string(self) -> None:
        """Returns a string token."""
        handler = JWTHandler()
        token = handler.create_refresh_token(user_id="user-123")

        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_refresh_token_correct_claims_with_7_day_expiry(self) -> None:
        """Creates token with correct claims and 7 day expiry."""
        handler = JWTHandler()
        token = handler.create_refresh_token(user_id="user-123")

        claims = handler.decode_token(token)

        assert claims.user_id == "user-123"
        assert claims.type == "refresh"
        assert claims.exp is not None
        assert claims.iat is not None
        assert claims.exp - claims.iat == 604800

    def test_create_refresh_token_with_session_id(self) -> None:
        """Creates refresh token with session ID."""
        handler = JWTHandler()
        token = handler.create_refresh_token(
            user_id="user-123", session_id="session-456"
        )

        claims = handler.decode_token(token)

        assert claims.session_id == "session-456"

    def test_create_refresh_token_custom_lifetime(self) -> None:
        """Creates refresh token with custom lifetime."""
        handler = JWTHandler()
        custom_lifetime = timedelta(days=30)
        token = handler.create_refresh_token(
            user_id="user-123", lifetime=custom_lifetime
        )

        claims = handler.decode_token(token)

        assert claims.exp - claims.iat == 30 * 24 * 60 * 60


class TestJWTHandlerEncodeDecodeToken:
    """Tests for JWTHandler encode_token and decode_token methods."""

    def test_encode_decode_token_roundtrip(self) -> None:
        """Token encoding and decoding roundtrip."""
        handler = JWTHandler()
        claims = TokenClaims(
            user_id="user-123",
            roles=["admin"],
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="test-jti",
            iss="securAIty",
            aud="securAIty-api",
        )

        token = handler.encode_token(claims)
        decoded = handler.decode_token(token)

        assert decoded.user_id == claims.user_id
        assert decoded.roles == claims.roles
        assert decoded.jti == claims.jti

    def test_decode_token_invalid_format_raises_error(self) -> None:
        """Invalid token format raises JWTDecodeError."""
        handler = JWTHandler()

        with pytest.raises(JWTDecodeError, match="Invalid token format"):
            handler.decode_token("invalid.token")

    def test_decode_token_invalid_signature_raises_error(self) -> None:
        """Invalid signature raises JWTDecodeError."""
        handler1 = JWTHandler()
        handler2 = JWTHandler()

        token = handler1.create_access_token(user_id="user-123")

        with pytest.raises(JWTDecodeError, match="Invalid token signature"):
            handler2.decode_token(token)

    def test_decode_token_expired_raises_jwt_expired_error(self) -> None:
        """Expired token raises JWTExpiredError."""
        handler = JWTHandler()

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) - 100,
            iat=int(time.time()) - 200,
            jti="test-jti",
            iss="securAIty",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTExpiredError, match="Token has expired"):
            handler.decode_token(token)

    def test_decode_token_not_yet_valid_raises_error(self) -> None:
        """Token not yet valid raises JWTDecodeError."""
        handler = JWTHandler()

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            nbf=int(time.time()) + 3600,
            jti="test-jti",
            iss="securAIty",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTDecodeError, match="not yet valid"):
            handler.decode_token(token)

    def test_decode_token_wrong_issuer_raises_error(self) -> None:
        """Wrong issuer raises JWTInvalidClaimsError."""
        handler = JWTHandler(issuer="custom-issuer")

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="test-jti",
            iss="wrong-issuer",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTInvalidClaimsError, match="Invalid issuer"):
            handler.decode_token(token)

    def test_decode_token_wrong_audience_raises_error(self) -> None:
        """Wrong audience raises JWTInvalidClaimsError."""
        handler = JWTHandler(audience="custom-audience")

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="test-jti",
            iss="securAIty",
            aud="wrong-audience",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTInvalidClaimsError, match="Invalid audience"):
            handler.decode_token(token)

    def test_decode_token_missing_user_id_raises_error(self) -> None:
        """Missing user_id raises JWTInvalidClaimsError."""
        handler = JWTHandler()

        claims = TokenClaims(
            user_id="",
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="test-jti",
            iss="securAIty",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTInvalidClaimsError, match="Missing user_id"):
            handler.decode_token(token)

    def test_decode_token_missing_jti_raises_error(self) -> None:
        """Missing jti raises JWTInvalidClaimsError."""
        handler = JWTHandler()

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti=None,
            iss="securAIty",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTInvalidClaimsError, match="Missing jti"):
            handler.decode_token(token)

    def test_decode_token_skip_expiration_check(self) -> None:
        """Allows decoding expired token with verify_exp=False."""
        handler = JWTHandler()

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) - 100,
            iat=int(time.time()) - 200,
            jti="test-jti",
            iss="securAIty",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        decoded = handler.decode_token(token, verify_exp=False)

        assert decoded.user_id == "user-123"


class TestJWTHandlerVerifyTokenAsync:
    """Tests for JWTHandler verify_token_async method."""

    @pytest.mark.asyncio
    async def test_verify_token_async_valid_token(self) -> None:
        """Valid token verifies successfully."""
        handler = JWTHandler()
        token = handler.create_access_token(user_id="user-123")

        claims = await handler.verify_token_async(token)

        assert claims.user_id == "user-123"

    @pytest.mark.asyncio
    async def test_verify_token_async_revoked_token_raises_error(self) -> None:
        """Revoked token raises JWTRevokedError."""
        handler = JWTHandler()
        await handler._revocation_store.start()
        try:
            token = handler.create_access_token(user_id="user-123")
            claims = handler.decode_token(token)

            await handler._revocation_store.add(
                claims.jti, claims.user_id, claims.exp
            )

            with pytest.raises(JWTRevokedError, match="revoked"):
                await handler.verify_token_async(token)
        finally:
            await handler._revocation_store.stop()

    @pytest.mark.asyncio
    async def test_verify_token_async_expired_token_raises_error(self) -> None:
        """Expired token raises JWTExpiredError."""
        handler = JWTHandler()

        claims = TokenClaims(
            user_id="user-123",
            exp=int(time.time()) - 100,
            iat=int(time.time()) - 200,
            jti="test-jti",
            iss="securAIty",
            aud="securAIty-api",
        )
        token = handler.encode_token(claims)

        with pytest.raises(JWTExpiredError):
            await handler.verify_token_async(token)


class TestJWTHandlerCreateTokenPair:
    """Tests for JWTHandler create_token_pair method."""

    def test_create_token_pair_returns_token_pair(self) -> None:
        """Returns TokenPair with access and refresh tokens."""
        handler = JWTHandler()
        pair = handler.create_token_pair(user_id="user-123")

        assert isinstance(pair, TokenPair)
        assert isinstance(pair.access_token, str)
        assert isinstance(pair.refresh_token, str)

    def test_create_token_pair_access_token_valid(self) -> None:
        """Access token in pair is valid."""
        handler = JWTHandler()
        pair = handler.create_token_pair(user_id="user-123")

        claims = handler.decode_token(pair.access_token)

        assert claims.user_id == "user-123"
        assert claims.type == "access"

    def test_create_token_pair_refresh_token_valid(self) -> None:
        """Refresh token in pair is valid."""
        handler = JWTHandler()
        pair = handler.create_token_pair(user_id="user-123")

        claims = handler.decode_token(pair.refresh_token)

        assert claims.user_id == "user-123"
        assert claims.type == "refresh"

    def test_create_token_pair_with_roles_permissions(self) -> None:
        """Creates pair with roles and permissions."""
        handler = JWTHandler()
        pair = handler.create_token_pair(
            user_id="user-123",
            roles=["admin"],
            permissions=["read", "write"],
        )

        access_claims = handler.decode_token(pair.access_token)

        assert access_claims.roles == ["admin"]
        assert access_claims.permissions == ["read", "write"]


class TestJWTHandlerRefreshAccessToken:
    """Tests for JWTHandler refresh_access_token method."""

    def test_refresh_access_token_returns_new_token_pair(self) -> None:
        """Returns new TokenPair with rotated tokens."""
        handler = JWTHandler()
        original_pair = handler.create_token_pair(user_id="user-123")

        new_pair = handler.refresh_access_token(original_pair.refresh_token)

        assert isinstance(new_pair, TokenPair)
        assert new_pair.access_token != original_pair.access_token
        assert new_pair.refresh_token != original_pair.refresh_token

    def test_refresh_access_token_new_tokens_valid(self) -> None:
        """New tokens are valid."""
        handler = JWTHandler()
        original_pair = handler.create_token_pair(user_id="user-123")

        new_pair = handler.refresh_access_token(original_pair.refresh_token)

        access_claims = handler.decode_token(new_pair.access_token)
        refresh_claims = handler.decode_token(new_pair.refresh_token)

        assert access_claims.user_id == "user-123"
        assert refresh_claims.user_id == "user-123"

    def test_refresh_access_token_invalid_refresh_token_raises_error(self) -> None:
        """Invalid refresh token raises JWTDecodeError."""
        handler = JWTHandler()

        with pytest.raises(JWTDecodeError):
            handler.refresh_access_token("invalid_token")

    def test_refresh_access_token_access_token_as_refresh_raises_error(self) -> None:
        """Using access token as refresh token raises error."""
        handler = JWTHandler()
        pair = handler.create_token_pair(user_id="user-123")

        with pytest.raises(JWTInvalidClaimsError, match="not a refresh token"):
            handler.refresh_access_token(pair.access_token)


class TestJWTHandlerRevokeToken:
    """Tests for JWTHandler revoke_token method."""

    @pytest.mark.asyncio
    async def test_revoke_token_adds_to_revocation_store(self) -> None:
        """Revoked token is added to revocation store."""
        handler = JWTHandler()
        await handler._revocation_store.start()
        try:
            token = handler.create_access_token(user_id="user-123")
            claims = handler.decode_token(token)

            await handler.revoke_token(token)

            is_revoked = await handler._revocation_store.is_revoked(claims.jti)
            assert is_revoked is True
        finally:
            await handler._revocation_store.stop()

    @pytest.mark.asyncio
    async def test_revoke_token_invalid_token_does_not_raise(self) -> None:
        """Revoking invalid token does not raise exception."""
        handler = JWTHandler()
        await handler._revocation_store.start()
        try:
            await handler.revoke_token("invalid_token")
        finally:
            await handler._revocation_store.stop()


class TestJWTHandlerRevokeAllUserTokens:
    """Tests for JWTHandler revoke_all_user_tokens method."""

    @pytest.mark.asyncio
    async def test_revoke_all_user_tokens(self) -> None:
        """Revokes all tokens for a user."""
        handler = JWTHandler()
        await handler._revocation_store.start()
        try:
            pair1 = handler.create_token_pair(user_id="user-123")
            pair2 = handler.create_token_pair(user_id="user-123")
            pair3 = handler.create_token_pair(user_id="user-456")

            count = await handler.revoke_all_user_tokens("user-123")

            assert count == 2

            access_claims1 = handler.decode_token(pair1.access_token)
            access_claims2 = handler.decode_token(pair2.access_token)
            access_claims3 = handler.decode_token(pair3.access_token)

            assert await handler._revocation_store.is_revoked(access_claims1.jti)
            assert await handler._revocation_store.is_revoked(access_claims2.jti)
            assert not await handler._revocation_store.is_revoked(
                access_claims3.jti
            )
        finally:
            await handler._revocation_store.stop()


class TestJWTHandlerKeyExport:
    """Tests for JWTHandler key export methods."""

    def test_get_public_key_pem_returns_bytes(self) -> None:
        """Returns PEM-encoded public key as bytes."""
        handler = JWTHandler()
        pem = handler.get_public_key_pem()

        assert isinstance(pem, bytes)
        assert b"-----BEGIN PUBLIC KEY-----" in pem

    def test_get_private_key_pem_returns_bytes(self) -> None:
        """Returns PEM-encoded private key as bytes."""
        handler = JWTHandler()
        pem = handler.get_private_key_pem()

        assert isinstance(pem, bytes)
        assert b"-----BEGIN PRIVATE KEY-----" in pem

    def test_get_private_key_pem_with_password(self) -> None:
        """Returns encrypted private key with password."""
        handler = JWTHandler()
        password = b"test_password"
        pem = handler.get_private_key_pem(password=password)

        assert isinstance(pem, bytes)
        assert b"ENCRYPTED" in pem
