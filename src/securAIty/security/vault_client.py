"""
HashiCorp Vault Client

Async client for HashiCorp Vault secrets management with AppRole authentication,
dynamic secrets support, and automatic lease renewal.
"""

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import hvac
from hvac.exceptions import InvalidPath, VaultError

from .exceptions import (
    VaultAuthenticationError,
    VaultConnectionError,
    VaultLeaseError,
    VaultPermissionError,
    VaultSecretNotFoundError,
    VaultError as SecurAItyVaultError,
)


@dataclass
class VaultConfig:
    """
    Configuration for Vault client connection.

    Attributes:
        url: Vault server URL
        token: Static Vault token (alternative to AppRole)
        approle_role_id: AppRole role ID for authentication
        approle_secret_id: AppRole secret ID for authentication
        namespace: Vault namespace (for Vault Enterprise)
        verify: Verify TLS certificate
        timeout: Request timeout in seconds
        retry_count: Number of retry attempts
        retry_delay: Delay between retries in seconds
    """

    url: str = field(default_factory=lambda: os.getenv("VAULT_URL", "http://localhost:8200"))
    token: Optional[str] = None
    approle_role_id: Optional[str] = None
    approle_secret_id: Optional[str] = None
    namespace: Optional[str] = None
    verify: bool = True
    timeout: int = 30
    retry_count: int = 3
    retry_delay: float = 1.0

    def __post_init__(self) -> None:
        # Load from environment if not provided
        if self.token is None:
            self.token = os.getenv("VAULT_TOKEN")
        if self.approle_role_id is None:
            self.approle_role_id = os.getenv("VAULT_ROLE_ID")
        if self.approle_secret_id is None:
            self.approle_secret_id = os.getenv("VAULT_SECRET_ID")

        # TLS verification
        verify_env = os.getenv("VAULT_SKIP_VERIFY", "false").lower()
        if verify_env in ("true", "1", "yes"):
            self.verify = False

        ca_cert = os.getenv("VAULT_CACERT")
        if ca_cert:
            self.verify = ca_cert

    @classmethod
    def from_environment(cls) -> "VaultConfig":
        """Create configuration from environment variables."""
        return cls()


@dataclass
class SecretLease:
    """
    Track dynamic secret lease information.

    Attributes:
        lease_id: Unique lease identifier
        lease_duration: Lease duration in seconds
        lease_start: When lease was acquired
        renewable: Whether lease can be renewed
        secret_path: Path to the secret
        secret_data: The actual secret data
    """

    lease_id: str
    lease_duration: int
    lease_start: datetime = field(default_factory=datetime.utcnow)
    renewable: bool = False
    secret_path: str = ""
    secret_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def expires_at(self) -> datetime:
        """Calculate lease expiration time."""
        return self.lease_start + timedelta(seconds=self.lease_duration)

    @property
    def is_expired(self) -> bool:
        """Check if lease has expired."""
        return datetime.utcnow() >= self.expires_at

    @property
    def time_to_expiry(self) -> timedelta:
        """Get remaining time until lease expires."""
        return self.expires_at - datetime.utcnow()

    @property
    def should_renew(self) -> bool:
        """Check if lease should be renewed (within 20% of expiry)."""
        if not self.renewable:
            return False
        renewal_threshold = self.lease_duration * 0.8
        elapsed = (datetime.utcnow() - self.lease_start).total_seconds()
        return elapsed >= renewal_threshold


class VaultClient:
    """
    Async HashiCorp Vault client for secrets management.

    Provides secure secret retrieval, dynamic secrets with lease management,
    AppRole authentication, and automatic token renewal for the securAIty platform.

    Attributes:
        config: Vault configuration
        _client: Underlying hvac client
        _token: Current Vault token
        _leases: Active secret leases
        _is_authenticated: Authentication state
    """

    def __init__(self, config: Optional[VaultConfig] = None) -> None:
        """
        Initialize Vault client.

        Args:
            config: Optional custom configuration
        """
        self.config = config or VaultConfig()
        self._client: Optional[hvac.Client] = None
        self._token: Optional[str] = None
        self._leases: Dict[str, SecretLease] = {}
        self._is_authenticated = False
        self._auth_lock = asyncio.Lock()
        self._renewal_tasks: set[asyncio.Task] = set()

    async def connect(self) -> None:
        """
        Establish connection to Vault and authenticate.

        Uses AppRole authentication if configured, otherwise falls back
        to static token authentication.

        Raises:
            VaultConnectionError: If connection fails
            VaultAuthenticationError: If authentication fails
        """
        async with self._auth_lock:
            if self._is_authenticated:
                return

            try:
                self._client = hvac.Client(
                    url=self.config.url,
                    token=self.config.token,
                    namespace=self.config.namespace,
                    verify=self.config.verify,
                    timeout=self.config.timeout,
                )

                # Check if already authenticated with token
                if self.config.token:
                    try:
                        if self._client.is_authenticated():
                            self._token = self.config.token
                            self._is_authenticated = True
                            return
                    except Exception:
                        pass

                # Use AppRole authentication
                if self.config.approle_role_id and self.config.approle_secret_id:
                    await self._approle_login()
                else:
                    raise VaultAuthenticationError(
                        "No authentication method configured. "
                        "Provide VAULT_TOKEN or VAULT_ROLE_ID/VAULT_SECRET_ID"
                    )

            except VaultError as e:
                raise VaultConnectionError(f"Failed to connect to Vault: {e}") from e
            except Exception as e:
                raise VaultConnectionError(f"Vault connection failed: {e}") from e

    async def _approle_login(self) -> None:
        """
        Authenticate using AppRole.

        Raises:
            VaultAuthenticationError: If AppRole authentication fails
        """
        if not self._client:
            raise VaultConnectionError("Vault client not initialized")

        try:
            response = self._client.auth.approle.login(
                role_id=self.config.approle_role_id,
                secret_id=self.config.approle_secret_id,
            )

            if response and "auth" in response and "client_token" in response["auth"]:
                self._token = response["auth"]["client_token"]
                self._client.token = self._token
                self._is_authenticated = True

                # Schedule token renewal if TTL provided
                if "lease_duration" in response["auth"]:
                    lease_duration = response["auth"]["lease_duration"]
                    if lease_duration > 60:  # Only renew if lease > 1 minute
                        await self._schedule_token_renewal(lease_duration)
            else:
                raise VaultAuthenticationError("Invalid response from AppRole login")

        except InvalidPath as e:
            raise VaultAuthenticationError(f"AppRole path invalid: {e}") from e
        except Exception as e:
            raise VaultAuthenticationError(f"AppRole authentication failed: {e}") from e

    async def _schedule_token_renewal(self, lease_duration: int) -> None:
        """
        Schedule automatic token renewal.

        Args:
            lease_duration: Current token lease duration in seconds
        """
        # Renew at 80% of lease duration
        renewal_delay = lease_duration * 0.8

        async def renew_token_task() -> None:
            await asyncio.sleep(renewal_delay)
            if self._is_authenticated:
                await self._renew_token()

        task = asyncio.create_task(renew_token_task())
        self._renewal_tasks.add(task)
        task.add_done_callback(self._renewal_tasks.discard)

    async def _renew_token(self) -> None:
        """
        Renew the current Vault token.

        Raises:
            VaultAuthenticationError: If token renewal fails
        """
        if not self._client or not self._token:
            raise VaultAuthenticationError("No token to renew")

        try:
            response = self._client.auth.token.renew_self()

            if response and "auth" in response and "lease_duration" in response["auth"]:
                new_lease_duration = response["auth"]["lease_duration"]
                await self._schedule_token_renewal(new_lease_duration)
            else:
                raise VaultAuthenticationError("Invalid response from token renewal")

        except Exception as e:
            raise VaultAuthenticationError(f"Token renewal failed: {e}") from e

    async def disconnect(self) -> None:
        """
        Gracefully disconnect from Vault.

        Revokes all dynamic leases and cancels renewal tasks.
        """
        async with self._auth_lock:
            # Cancel renewal tasks
            for task in self._renewal_tasks:
                task.cancel()
            self._renewal_tasks.clear()

            # Revoke all leases
            for lease_id in list(self._leases.keys()):
                await self.revoke_lease(lease_id)

            self._leases.clear()
            self._is_authenticated = False
            self._token = None

    async def get_secret(
        self,
        path: str,
        version: Optional[int] = None,
        mount_point: str = "secret",
    ) -> Dict[str, Any]:
        """
        Retrieve secret from Vault KV v2 engine.

        Args:
            path: Secret path (e.g., "myapp/database")
            version: Optional specific version (default: latest)
            mount_point: KV mount point (default: "secret")

        Returns:
            Secret data dictionary

        Raises:
            VaultSecretNotFoundError: If secret doesn't exist
            VaultPermissionError: If insufficient permissions
            VaultConnectionError: If connection fails
        """
        if not self._is_authenticated or not self._client:
            raise VaultConnectionError("Not connected to Vault")

        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point=mount_point,
            )

            if response and "data" in response and "data" in response["data"]:
                return response["data"]["data"]
            else:
                raise VaultSecretNotFoundError(f"Secret not found at path: {path}")

        except InvalidPath as e:
            raise VaultSecretNotFoundError(f"Secret not found: {path}") from e
        except VaultError as e:
            if "permission denied" in str(e).lower():
                raise VaultPermissionError(f"Permission denied for path: {path}") from e
            raise VaultConnectionError(f"Failed to read secret: {e}") from e

    async def set_secret(
        self,
        path: str,
        data: Dict[str, Any],
        mount_point: str = "secret",
    ) -> None:
        """
        Store secret in Vault KV v2 engine.

        Args:
            path: Secret path
            data: Secret data dictionary
            mount_point: KV mount point

        Raises:
            VaultPermissionError: If insufficient permissions
            VaultConnectionError: If connection fails
        """
        if not self._is_authenticated or not self._client:
            raise VaultConnectionError("Not connected to Vault")

        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=mount_point,
            )

        except VaultError as e:
            if "permission denied" in str(e).lower():
                raise VaultPermissionError(f"Permission denied for path: {path}") from e
            raise VaultConnectionError(f"Failed to write secret: {e}") from e

    async def delete_secret(
        self,
        path: str,
        mount_point: str = "secret",
    ) -> None:
        """
        Delete secret from Vault.

        Args:
            path: Secret path
            mount_point: KV mount point

        Raises:
            VaultPermissionError: If insufficient permissions
            VaultConnectionError: If connection fails
        """
        if not self._is_authenticated or not self._client:
            raise VaultConnectionError("Not connected to Vault")

        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=mount_point,
            )

        except VaultError as e:
            if "permission denied" in str(e).lower():
                raise VaultPermissionError(f"Permission denied for path: {path}") from e
            raise VaultConnectionError(f"Failed to delete secret: {e}") from e

    async def get_dynamic_secret(
        self,
        path: str,
        mount_point: str = "database",
    ) -> SecretLease:
        """
        Retrieve dynamic secret with lease management.

        Dynamic secrets are automatically revoked when no longer needed
        or when the client disconnects.

        Args:
            path: Secret path
            mount_point: Secrets engine mount point

        Returns:
            SecretLease with secret data and lease info

        Raises:
            VaultSecretNotFoundError: If secret doesn't exist
            VaultLeaseError: If lease acquisition fails
        """
        if not self._is_authenticated or not self._client:
            raise VaultConnectionError("Not connected to Vault")

        try:
            response = self._client.read(path)

            if not response:
                raise VaultSecretNotFoundError(f"Dynamic secret not found: {path}")

            lease = SecretLease(
                lease_id=response.get("lease_id", ""),
                lease_duration=response.get("lease_duration", 0),
                renewable=response.get("renewable", False),
                secret_path=path,
                secret_data=response.get("data", {}),
            )

            self._leases[lease.lease_id] = lease
            return lease

        except InvalidPath as e:
            raise VaultSecretNotFoundError(f"Dynamic secret not found: {path}") from e
        except Exception as e:
            raise VaultLeaseError(f"Failed to acquire dynamic secret lease: {e}") from e

    async def renew_lease(self, lease_id: str, increment: Optional[int] = None) -> SecretLease:
        """
        Renew a dynamic secret lease.

        Args:
            lease_id: Lease identifier to renew
            increment: Optional requested extension in seconds

        Returns:
            Updated SecretLease

        Raises:
            VaultLeaseError: If renewal fails
            VaultSecretNotFoundError: If lease not found
        """
        if not self._is_authenticated or not self._client:
            raise VaultConnectionError("Not connected to Vault")

        if lease_id not in self._leases:
            raise VaultSecretNotFoundError(f"Lease not found: {lease_id}")

        try:
            response = self._client.sys.renew_lease(
                lease_id=lease_id,
                increment=increment,
            )

            lease = self._leases[lease_id]
            lease.lease_duration = response.get("lease_duration", lease.lease_duration)
            lease.lease_start = datetime.utcnow()
            lease.renewable = response.get("renewable", False)

            return lease

        except Exception as e:
            raise VaultLeaseError(f"Failed to renew lease {lease_id}: {e}") from e

    async def revoke_lease(self, lease_id: str) -> None:
        """
        Revoke a dynamic secret lease.

        Args:
            lease_id: Lease identifier to revoke

        Raises:
            VaultLeaseError: If revocation fails
        """
        if not self._is_authenticated or not self._client:
            return  # Can't revoke if not connected

        try:
            self._client.sys.revoke_lease(lease_id=lease_id)
            self._leases.pop(lease_id, None)

        except Exception:
            # Lease may already be expired or revoked
            self._leases.pop(lease_id, None)

    async def list_secrets(
        self,
        path: str = "",
        mount_point: str = "secret",
    ) -> List[str]:
        """
        List secret paths at given location.

        Args:
            path: Path to list (empty for root)
            mount_point: KV mount point

        Returns:
            List of secret paths

        Raises:
            VaultPermissionError: If insufficient permissions
            VaultConnectionError: If connection fails
        """
        if not self._is_authenticated or not self._client:
            raise VaultConnectionError("Not connected to Vault")

        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=mount_point,
            )

            if response and "data" in response and "keys" in response["data"]:
                return response["data"]["keys"]
            return []

        except InvalidPath:
            return []
        except VaultError as e:
            if "permission denied" in str(e).lower():
                raise VaultPermissionError(f"Permission denied to list: {path}") from e
            raise VaultConnectionError(f"Failed to list secrets: {e}") from e

    async def health_check(self) -> Dict[str, Any]:
        """
        Check Vault server health status.

        Returns:
            Health status dictionary with initialized, sealed, standby info

        Raises:
            VaultConnectionError: If health check fails
        """
        if not self._client:
            raise VaultConnectionError("Vault client not initialized")

        try:
            health = self._client.sys.read_health_status()

            if isinstance(health, dict):
                return health
            elif hasattr(health, "__dict__"):
                return vars(health)
            else:
                return {"status": "unknown"}

        except Exception as e:
            raise VaultConnectionError(f"Health check failed: {e}") from e

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._is_authenticated

    @property
    def token(self) -> Optional[str]:
        """Get current Vault token."""
        return self._token

    async def __aenter__(self) -> "VaultClient":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
