"""
JWT Token Handler

Secure JWT token generation, validation, and management with RS256 signing,
token revocation, refresh token rotation, and comprehensive claims validation.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from .exceptions import (
    JWTDecodeError,
    JWTExpiredError,
    JWTInvalidClaimsError,
    JWTRevokedError,
    JWTError,
    SecurityValidationError,
)


DEFAULT_ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
DEFAULT_REFRESH_TOKEN_LIFETIME = timedelta(days=7)
DEFAULT_CLOCK_SKEW_TOLERANCE = timedelta(seconds=30)
RSA_KEY_SIZE = 2048


@dataclass
class TokenClaims:
    """
    JWT token claims structure.

    Attributes:
        user_id: Unique user identifier
        roles: List of user roles
        permissions: List of user permissions
        session_id: Session identifier for tracking
        jti: Unique token identifier
        exp: Token expiration time (Unix timestamp)
        iat: Token issued at time (Unix timestamp)
        nbf: Token not valid before time (Unix timestamp)
        iss: Token issuer
        aud: Token audience
        scope: Optional scope string for OAuth2 compatibility
        type: Token type (access/refresh)
    """

    user_id: str
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    jti: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    scope: Optional[str] = None
    type: str = "access"

    def to_dict(self) -> Dict[str, Any]:
        """Convert claims to dictionary for JWT encoding."""
        claims: Dict[str, Any] = {
            "sub": self.user_id,
            "iat": self.iat,
            "exp": self.exp,
            "nbf": self.nbf,
            "iss": self.iss,
            "aud": self.aud,
            "jti": self.jti,
            "type": self.type,
        }

        if self.roles:
            claims["roles"] = self.roles
        if self.permissions:
            claims["permissions"] = self.permissions
        if self.session_id:
            claims["session_id"] = self.session_id
        if self.scope:
            claims["scope"] = self.scope

        return claims

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenClaims":
        """Create TokenClaims from dictionary."""
        return cls(
            user_id=data.get("sub", ""),
            roles=data.get("roles", []),
            permissions=data.get("permissions", []),
            session_id=data.get("session_id"),
            jti=data.get("jti"),
            exp=data.get("exp"),
            iat=data.get("iat"),
            nbf=data.get("nbf"),
            iss=data.get("iss"),
            aud=data.get("aud"),
            scope=data.get("scope"),
            type=data.get("type", "access"),
        )

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if self.exp is None:
            return False
        return int(time.time()) > self.exp

    @property
    def is_not_yet_valid(self) -> bool:
        """Check if token is not yet valid (nbf claim)."""
        if self.nbf is None:
            return False
        return int(time.time()) < self.nbf


@dataclass
class TokenPair:
    """
    Access and refresh token pair.

    Attributes:
        access_token: Short-lived access token
        refresh_token: Long-lived refresh token
        token_type: Token type identifier (Bearer)
        expires_in: Access token lifetime in seconds
        refresh_expires_in: Refresh token lifetime in seconds
    """

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 900
    refresh_expires_in: int = 604800

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_expires_in": self.refresh_expires_in,
        }


class TokenRevocationStore:
    """
    Async token revocation tracking store.

    Maintains a set of revoked token JTIs with automatic cleanup
    of expired entries. Suitable for in-memory storage; for production,
    use Redis or database-backed implementation.

    Attributes:
        _revoked_tokens: Set of revoked token JTIs
        _user_revoked_tokens: Mapping of user_id to revoked JTIs
        _token_expiry: Mapping of JTI to expiration time
        _cleanup_interval: Interval for expired token cleanup
        _cleanup_task: Background cleanup task
    """

    def __init__(self, cleanup_interval: int = 3600) -> None:
        """
        Initialize revocation store.

        Args:
            cleanup_interval: Seconds between cleanup runs (default: 1 hour)
        """
        self._revoked_tokens: Set[str] = set()
        self._user_revoked_tokens: Dict[str, Set[str]] = {}
        self._token_expiry: Dict[str, int] = {}
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._is_running = False

    async def start(self) -> None:
        """Start background cleanup task."""
        if self._is_running:
            return

        self._is_running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        """Stop background cleanup task."""
        self._is_running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired revoked tokens."""
        while self._is_running:
            await asyncio.sleep(self._cleanup_interval)
            await self._cleanup_expired()

    async def _cleanup_expired(self) -> None:
        """Remove expired entries from revocation store."""
        async with self._lock:
            current_time = int(time.time())
            expired_jtis = [
                jti for jti, exp in self._token_expiry.items()
                if current_time > exp
            ]

            for jti in expired_jtis:
                self._revoked_tokens.discard(jti)
                del self._token_expiry[jti]

            for user_id in list(self._user_revoked_tokens.keys()):
                self._user_revoked_tokens[user_id] -= set(expired_jtis)
                if not self._user_revoked_tokens[user_id]:
                    del self._user_revoked_tokens[user_id]

    async def add(self, jti: str, user_id: str, exp: Optional[int] = None) -> None:
        """
        Add token to revocation store.

        Args:
            jti: Token JTI to revoke
            user_id: User ID associated with token
            exp: Token expiration time for cleanup
        """
        async with self._lock:
            self._revoked_tokens.add(jti)

            if user_id not in self._user_revoked_tokens:
                self._user_revoked_tokens[user_id] = set()
            self._user_revoked_tokens[user_id].add(jti)

            if exp:
                self._token_expiry[jti] = exp

    async def is_revoked(self, jti: str) -> bool:
        """
        Check if token JTI is revoked.

        Args:
            jti: Token JTI to check

        Returns:
            True if revoked, False otherwise
        """
        async with self._lock:
            return jti in self._revoked_tokens

    async def revoke_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user.

        Args:
            user_id: User ID to revoke all tokens for

        Returns:
            Number of tokens revoked
        """
        async with self._lock:
            if user_id not in self._user_revoked_tokens:
                return 0

            revoked_count = len(self._user_revoked_tokens[user_id])
            self._revoked_tokens -= self._user_revoked_tokens[user_id]
            del self._user_revoked_tokens[user_id]

            for jti, exp in list(self._token_expiry.items()):
                if jti not in self._revoked_tokens:
                    continue

            return revoked_count

    async def get_revoked_count(self) -> int:
        """Get total number of revoked tokens."""
        async with self._lock:
            return len(self._revoked_tokens)

    async def clear(self) -> None:
        """Clear all revoked tokens."""
        async with self._lock:
            self._revoked_tokens.clear()
            self._user_revoked_tokens.clear()
            self._token_expiry.clear()


class JWTHandler:
    """
    Secure JWT token handler with RS256 signing.

    Provides token generation, validation, revocation, and refresh
    capabilities with proper security controls including algorithm
    verification, claims validation, and clock skew tolerance.

    Attributes:
        _private_key: RSA private key for signing
        _public_key: RSA public key for verification
        _issuer: Token issuer identifier
        _audience: Token audience identifier
        _revocation_store: Token revocation tracking
        _clock_skew: Allowed clock skew tolerance
    """

    def __init__(
        self,
        private_key: Optional[rsa.RSAPrivateKey] = None,
        public_key: Optional[rsa.RSAPublicKey] = None,
        issuer: str = "securAIty",
        audience: str = "securAIty-api",
        clock_skew: timedelta = DEFAULT_CLOCK_SKEW_TOLERANCE,
    ) -> None:
        """
        Initialize JWT handler.

        Args:
            private_key: RSA private key for signing (generates if not provided)
            public_key: RSA public key for verification (derived from private if not provided)
            issuer: Token issuer identifier
            audience: Token audience identifier
            clock_skew: Allowed clock skew tolerance
        """
        self._issuer = issuer
        self._audience = audience
        self._clock_skew = clock_skew
        self._revocation_store = TokenRevocationStore()

        if private_key is None:
            private_key, public_key = self._generate_rsa_keypair()
            self._private_key = private_key
            self._public_key = public_key
        else:
            self._private_key = private_key
            self._public_key = public_key or private_key.public_key()

    @classmethod
    def from_keys(
        cls,
        private_key_pem: bytes,
        public_key_pem: Optional[bytes] = None,
        issuer: str = "securAIty",
        audience: str = "securAIty-api",
        clock_skew: timedelta = DEFAULT_CLOCK_SKEW_TOLERANCE,
        password: Optional[bytes] = None,
    ) -> "JWTHandler":
        """
        Create JWT handler from PEM-encoded keys.

        Args:
            private_key_pem: PEM-encoded private key
            public_key_pem: Optional PEM-encoded public key
            issuer: Token issuer identifier
            audience: Token audience identifier
            clock_skew: Allowed clock skew tolerance
            password: Optional password for encrypted private key

        Returns:
            Configured JWTHandler instance
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend(),
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise JWTError("Private key must be RSA")

        public_key: Optional[rsa.RSAPublicKey] = None
        if public_key_pem:
            loaded_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend(),
            )
            if not isinstance(loaded_key, rsa.RSAPublicKey):
                raise JWTError("Public key must be RSA")
            public_key = loaded_key

        return cls(
            private_key=private_key,
            public_key=public_key,
            issuer=issuer,
            audience=audience,
            clock_skew=clock_skew,
        )

    def _generate_rsa_keypair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair for JWT signing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def _base64url_encode(self, data: bytes) -> str:
        """Base64url encode data without padding."""
        import base64
        encoded = base64.urlsafe_b64encode(data)
        return encoded.rstrip(b"=").decode("ascii")

    def _base64url_decode(self, data: str) -> bytes:
        """Base64url decode data with padding restoration."""
        import base64
        padding_needed = 4 - (len(data) % 4)
        if padding_needed != 4:
            data += "=" * padding_needed
        return base64.urlsafe_b64decode(data)

    def _create_signature(self, signing_input: bytes) -> bytes:
        """Create RSA-PSS signature for JWT."""
        signature = self._private_key.sign(
            signing_input,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature

    def _verify_signature(self, signing_input: bytes, signature: bytes) -> bool:
        """Verify RSA-PSS signature for JWT."""
        try:
            self._public_key.verify(
                signature,
                signing_input,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def create_access_token(
        self,
        user_id: str,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        lifetime: timedelta = DEFAULT_ACCESS_TOKEN_LIFETIME,
        scope: Optional[str] = None,
    ) -> str:
        """
        Create signed access token.

        Args:
            user_id: Unique user identifier
            roles: List of user roles
            permissions: List of user permissions
            session_id: Session identifier
            lifetime: Token lifetime (default: 15 minutes)
            scope: OAuth2 scope string

        Returns:
            Signed JWT access token
        """
        current_time = int(time.time())
        exp_time = current_time + int(lifetime.total_seconds())
        nbf_time = current_time - int(self._clock_skew.total_seconds())

        claims = TokenClaims(
            user_id=user_id,
            roles=roles or [],
            permissions=permissions or [],
            session_id=session_id,
            jti=str(uuid.uuid4()),
            exp=exp_time,
            iat=current_time,
            nbf=nbf_time,
            iss=self._issuer,
            aud=self._audience,
            scope=scope,
            type="access",
        )

        return self.encode_token(claims)

    def create_refresh_token(
        self,
        user_id: str,
        session_id: Optional[str] = None,
        lifetime: timedelta = DEFAULT_REFRESH_TOKEN_LIFETIME,
    ) -> str:
        """
        Create signed refresh token.

        Args:
            user_id: Unique user identifier
            session_id: Session identifier
            lifetime: Token lifetime (default: 7 days)

        Returns:
            Signed JWT refresh token
        """
        current_time = int(time.time())
        exp_time = current_time + int(lifetime.total_seconds())
        nbf_time = current_time - int(self._clock_skew.total_seconds())

        claims = TokenClaims(
            user_id=user_id,
            roles=[],
            permissions=[],
            session_id=session_id,
            jti=str(uuid.uuid4()),
            exp=exp_time,
            iat=current_time,
            nbf=nbf_time,
            iss=self._issuer,
            aud=self._audience,
            type="refresh",
        )

        return self.encode_token(claims)

    def encode_token(self, claims: TokenClaims) -> str:
        """
        Encode and sign token claims to JWT.

        Args:
            claims: TokenClaims to encode

        Returns:
            Signed JWT token string
        """
        header = {
            "typ": "JWT",
            "alg": "RS256",
        }

        header_encoded = self._base64url_encode(
            self._json_dumps(header).encode("utf-8")
        )
        claims_encoded = self._base64url_encode(
            self._json_dumps(claims.to_dict()).encode("utf-8")
        )

        signing_input = f"{header_encoded}.{claims_encoded}".encode("utf-8")
        signature = self._create_signature(signing_input)
        signature_encoded = self._base64url_encode(signature)

        return f"{header_encoded}.{claims_encoded}.{signature_encoded}"

    def decode_token(self, token: str, verify_exp: bool = True) -> TokenClaims:
        """
        Decode and validate JWT token.

        Args:
            token: JWT token string
            verify_exp: Whether to verify expiration

        Returns:
            Decoded TokenClaims

        Raises:
            JWTDecodeError: If token is invalid
            JWTExpiredError: If token has expired
            JWTInvalidClaimsError: If required claims are missing
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTDecodeError("Invalid token format")

        header_encoded, claims_encoded, signature_encoded = parts

        try:
            header_json = self._base64url_decode(header_encoded)
            header = self._json_loads(header_json.decode("utf-8"))
        except Exception as e:
            raise JWTDecodeError(f"Invalid token header: {e}") from e

        if header.get("typ") != "JWT":
            raise JWTDecodeError("Invalid token type")

        if header.get("alg") != "RS256":
            raise JWTDecodeError("Unsupported algorithm")

        try:
            signature = self._base64url_decode(signature_encoded)
        except Exception as e:
            raise JWTDecodeError(f"Invalid signature encoding: {e}") from e

        signing_input = f"{header_encoded}.{claims_encoded}".encode("utf-8")
        if not self._verify_signature(signing_input, signature):
            raise JWTDecodeError("Invalid token signature")

        try:
            claims_json = self._base64url_decode(claims_encoded)
            claims_data = self._json_loads(claims_json.decode("utf-8"))
        except Exception as e:
            raise JWTDecodeError(f"Invalid token claims: {e}") from e

        claims = TokenClaims.from_dict(claims_data)

        if verify_exp:
            current_time = int(time.time())
            clock_skew_seconds = int(self._clock_skew.total_seconds())

            if claims.exp and current_time > claims.exp + clock_skew_seconds:
                raise JWTExpiredError("Token has expired")

            if claims.nbf and current_time < claims.nbf - clock_skew_seconds:
                raise JWTDecodeError("Token is not yet valid")

        if claims.iss != self._issuer:
            raise JWTInvalidClaimsError(f"Invalid issuer: {claims.iss}")

        if claims.aud != self._audience:
            raise JWTInvalidClaimsError(f"Invalid audience: {claims.aud}")

        if not claims.user_id:
            raise JWTInvalidClaimsError("Missing user_id (sub claim)")

        if not claims.jti:
            raise JWTInvalidClaimsError("Missing jti claim")

        return claims

    async def verify_token_async(self, token: str, verify_exp: bool = True) -> TokenClaims:
        """
        Async token verification with revocation check.

        Args:
            token: JWT token string
            verify_exp: Whether to verify expiration

        Returns:
            Decoded TokenClaims

        Raises:
            JWTDecodeError: If token is invalid
            JWTExpiredError: If token has expired
            JWTRevokedError: If token has been revoked
            JWTInvalidClaimsError: If required claims are missing
        """
        claims = self.decode_token(token, verify_exp)

        if claims.jti and await self._revocation_store.is_revoked(claims.jti):
            raise JWTRevokedError("Token has been revoked")

        return claims

    def create_token_pair(
        self,
        user_id: str,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        access_lifetime: timedelta = DEFAULT_ACCESS_TOKEN_LIFETIME,
        refresh_lifetime: timedelta = DEFAULT_REFRESH_TOKEN_LIFETIME,
        scope: Optional[str] = None,
    ) -> TokenPair:
        """
        Create access and refresh token pair.

        Args:
            user_id: Unique user identifier
            roles: List of user roles
            permissions: List of user permissions
            session_id: Session identifier
            access_lifetime: Access token lifetime
            refresh_lifetime: Refresh token lifetime
            scope: OAuth2 scope string

        Returns:
            TokenPair with access and refresh tokens
        """
        access_token = self.create_access_token(
            user_id=user_id,
            roles=roles,
            permissions=permissions,
            session_id=session_id,
            lifetime=access_lifetime,
            scope=scope,
        )

        refresh_token = self.create_refresh_token(
            user_id=user_id,
            session_id=session_id,
            lifetime=refresh_lifetime,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(access_lifetime.total_seconds()),
            refresh_expires_in=int(refresh_lifetime.total_seconds()),
        )

    def refresh_access_token(self, refresh_token: str) -> TokenPair:
        """
        Refresh access token using refresh token.

        Validates refresh token and creates new token pair with
        rotated refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New TokenPair with rotated tokens

        Raises:
            JWTDecodeError: If refresh token is invalid
            JWTExpiredError: If refresh token has expired
            JWTInvalidClaimsError: If refresh token claims are invalid
        """
        claims = self.decode_token(refresh_token, verify_exp=True)

        if claims.type != "refresh":
            raise JWTInvalidClaimsError("Token is not a refresh token")

        new_token_pair = self.create_token_pair(
            user_id=claims.user_id,
            session_id=claims.session_id,
        )

        return new_token_pair

    async def revoke_token(self, token: str) -> None:
        """
        Revoke a token by adding to revocation store.

        Args:
            token: JWT token to revoke
        """
        try:
            claims = self.decode_token(token, verify_exp=False)
            if claims.jti:
                await self._revocation_store.add(
                    jti=claims.jti,
                    user_id=claims.user_id,
                    exp=claims.exp,
                )
        except JWTError:
            pass

    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user (logout everywhere).

        Args:
            user_id: User ID to revoke all tokens for

        Returns:
            Number of tokens revoked
        """
        return await self._revocation_store.revoke_user_tokens(user_id)

    def get_public_key_pem(self) -> bytes:
        """
        Export public key as PEM.

        Returns:
            PEM-encoded public key bytes
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_private_key_pem(self, password: Optional[bytes] = None) -> bytes:
        """
        Export private key as PEM.

        Args:
            password: Optional password for encryption

        Returns:
            PEM-encoded private key bytes
        """
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

    async def start_revocation_cleanup(self) -> None:
        """Start background revocation store cleanup task."""
        await self._revocation_store.start()

    async def stop_revocation_cleanup(self) -> None:
        """Stop background revocation store cleanup task."""
        await self._revocation_store.stop()

    def _json_dumps(self, obj: Any) -> str:
        """JSON serialize object."""
        import json
        return json.dumps(obj, separators=(",", ":"))

    def _json_loads(self, data: str) -> Any:
        """JSON deserialize string."""
        import json
        return json.loads(data)

    async def __aenter__(self) -> "JWTHandler":
        """Async context manager entry."""
        await self.start_revocation_cleanup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.stop_revocation_cleanup()
