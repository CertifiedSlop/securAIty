"""
Unit tests for Vault client in securAIty security module.

Tests cover connection, authentication, secret operations,
lease management, and error handling with mocked hvac client.
"""

from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from securAIty.security.exceptions import (
    VaultAuthenticationError,
    VaultConnectionError,
    VaultLeaseError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)
from securAIty.security.vault_client import (
    SecretLease,
    VaultClient,
    VaultConfig,
)


class TestVaultConfig:
    """Tests for VaultConfig dataclass."""

    def test_vault_config_default_values(self) -> None:
        """Uses default values when not specified."""
        config = VaultConfig()

        assert config.url == "http://localhost:8200"
        assert config.token is None
        assert config.approle_role_id is None
        assert config.approle_secret_id is None
        assert config.namespace is None
        assert config.verify is True
        assert config.timeout == 30
        assert config.retry_count == 3
        assert config.retry_delay == 1.0

    def test_vault_config_custom_values(self) -> None:
        """Uses custom values when specified."""
        config = VaultConfig(
            url="https://vault.example.com",
            token="test-token",
            approle_role_id="role-id",
            approle_secret_id="secret-id",
            namespace="my-namespace",
            verify=False,
            timeout=60,
        )

        assert config.url == "https://vault.example.com"
        assert config.token == "test-token"
        assert config.approle_role_id == "role-id"
        assert config.approle_secret_id == "secret-id"
        assert config.namespace == "my-namespace"
        assert config.verify is False
        assert config.timeout == 60

    def test_vault_config_from_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loads configuration from environment variables."""
        monkeypatch.setenv("VAULT_URL", "https://env-vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "env-token")
        monkeypatch.setenv("VAULT_ROLE_ID", "env-role-id")
        monkeypatch.setenv("VAULT_SECRET_ID", "env-secret-id")

        config = VaultConfig.from_environment()

        assert config.url == "https://env-vault.example.com"
        assert config.token == "env-token"
        assert config.approle_role_id == "env-role-id"
        assert config.approle_secret_id == "env-secret-id"

    def test_vault_config_skip_verify_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sets verify=False from VAULT_SKIP_VERIFY environment."""
        monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")

        config = VaultConfig()

        assert config.verify is False

    def test_vault_config_ca_cert_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sets CA cert from VAULT_CACERT environment."""
        monkeypatch.setenv("VAULT_CACERT", "/path/to/ca.crt")

        config = VaultConfig()

        assert config.verify == "/path/to/ca.crt"


class TestSecretLease:
    """Tests for SecretLease dataclass."""

    def test_secret_lease_default_values(self) -> None:
        """Uses default values for optional fields."""
        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
        )

        assert lease.lease_id == "lease-123"
        assert lease.lease_duration == 3600
        assert lease.renewable is False
        assert lease.secret_path == ""
        assert lease.secret_data == {}

    def test_secret_lease_expires_at(self) -> None:
        """Calculates correct expiration time."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
            lease_start=datetime(2024, 1, 1, 12, 0, 0),
        )

        expected_expiry = datetime(2024, 1, 1, 13, 0, 0)
        assert lease.expires_at == expected_expiry

    def test_secret_lease_is_expired_true(self) -> None:
        """Returns True when lease is expired."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=60,
            lease_start=datetime.utcnow() - timedelta(seconds=120),
        )

        assert lease.is_expired is True

    def test_secret_lease_is_expired_false(self) -> None:
        """Returns False when lease is not expired."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
            lease_start=datetime.utcnow(),
        )

        assert lease.is_expired is False

    def test_secret_lease_time_to_expiry(self) -> None:
        """Calculates remaining time to expiry."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
            lease_start=datetime.utcnow() - timedelta(seconds=1800),
        )

        remaining = lease.time_to_expiry
        assert remaining.total_seconds() == pytest.approx(1800, abs=1)

    def test_secret_lease_should_renew_true(self) -> None:
        """Returns True when lease should be renewed."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=100,
            lease_start=datetime.utcnow() - timedelta(seconds=85),
            renewable=True,
        )

        assert lease.should_renew is True

    def test_secret_lease_should_renew_false_not_renewable(self) -> None:
        """Returns False when lease is not renewable."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=100,
            lease_start=datetime.utcnow() - timedelta(seconds=85),
            renewable=False,
        )

        assert lease.should_renew is False

    def test_secret_lease_should_renew_false_too_early(self) -> None:
        """Returns False when too early to renew."""
        from datetime import datetime, timedelta

        lease = SecretLease(
            lease_id="lease-123",
            lease_duration=100,
            lease_start=datetime.utcnow() - timedelta(seconds=50),
            renewable=True,
        )

        assert lease.should_renew is False


class TestVaultClientInitialization:
    """Tests for VaultClient initialization."""

    def test_vault_client_initialization_default_config(self) -> None:
        """Initializes with default configuration."""
        client = VaultClient()

        assert client.config is not None
        assert client._is_authenticated is False
        assert client._client is None
        assert client._token is None
        assert client._leases == {}

    def test_vault_client_initialization_custom_config(self) -> None:
        """Initializes with custom configuration."""
        config = VaultConfig(url="https://custom-vault.example.com")
        client = VaultClient(config=config)

        assert client.config.url == "https://custom-vault.example.com"


class TestVaultClientConnect:
    """Tests for VaultClient connect method."""

    @pytest.mark.asyncio
    async def test_vault_client_connect_with_token_authentication(self) -> None:
        """Connects successfully with static token."""
        config = VaultConfig(
            url="http://localhost:8200",
            token="test-token",
        )
        client = VaultClient(config=config)

        mock_hvac_client = MagicMock()
        mock_hvac_client.is_authenticated.return_value = True
        mock_hvac_client.token = "test-token"

        with patch(
            "securAIty.security.vault_client.hvac.Client",
            return_value=mock_hvac_client,
        ):
            await client.connect()

            assert client._is_authenticated is True
            assert client._token == "test-token"

    @pytest.mark.asyncio
    async def test_vault_client_connect_with_approle_authentication(self) -> None:
        """Connects successfully with AppRole authentication."""
        config = VaultConfig(
            url="http://localhost:8200",
            approle_role_id="test-role-id",
            approle_secret_id="test-secret-id",
        )
        client = VaultClient(config=config)

        mock_hvac_client = MagicMock()
        mock_hvac_client.is_authenticated.return_value = False
        mock_hvac_client.auth.approle.login.return_value = {
            "auth": {
                "client_token": "approle-token",
                "lease_duration": 3600,
            }
        }

        with patch(
            "securAIty.security.vault_client.hvac.Client",
            return_value=mock_hvac_client,
        ):
            await client.connect()

            assert client._is_authenticated is True
            assert client._token == "approle-token"

    @pytest.mark.asyncio
    async def test_vault_client_connect_no_auth_method_raises_error(self) -> None:
        """Raises error when no authentication method configured."""
        config = VaultConfig(url="http://localhost:8200")
        client = VaultClient(config=config)

        mock_hvac_client = MagicMock()
        mock_hvac_client.is_authenticated.return_value = False

        with patch(
            "securAIty.security.vault_client.hvac.Client",
            return_value=mock_hvac_client,
        ):
            with pytest.raises(VaultAuthenticationError, match="No authentication method"):
                await client.connect()

    @pytest.mark.asyncio
    async def test_vault_client_connect_connection_failure_raises_error(self) -> None:
        """Raises error on connection failure."""
        config = VaultConfig(url="http://localhost:8200", token="test-token")
        client = VaultClient(config=config)

        with patch(
            "securAIty.security.vault_client.hvac.Client",
            side_effect=Exception("Connection refused"),
        ):
            with pytest.raises(VaultConnectionError, match="Vault connection failed"):
                await client.connect()

    @pytest.mark.asyncio
    async def test_vault_client_connect_already_authenticated(self) -> None:
        """Skips connection if already authenticated."""
        config = VaultConfig(url="http://localhost:8200", token="test-token")
        client = VaultClient(config=config)
        client._is_authenticated = True

        with patch(
            "securAIty.security.vault_client.hvac.Client",
        ) as mock_client:
            await client.connect()

            mock_client.assert_not_called()


class TestVaultClientGetSecret:
    """Tests for VaultClient get_secret method."""

    @pytest.mark.asyncio
    async def test_vault_client_get_secret_success(self) -> None:
        """Retrieves secret successfully."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "username": "db_user",
                    "password": "db_password",
                }
            }
        }
        client._client = mock_hvac_client

        result = await client.get_secret("myapp/database")

        assert result == {"username": "db_user", "password": "db_password"}

    @pytest.mark.asyncio
    async def test_vault_client_get_secret_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        with pytest.raises(VaultConnectionError, match="Not connected"):
            await client.get_secret("myapp/database")

    @pytest.mark.asyncio
    async def test_vault_client_get_secret_not_found_raises_error(self) -> None:
        """Raises error when secret not found."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = None
        client._client = mock_hvac_client

        with pytest.raises(VaultSecretNotFoundError, match="Secret not found"):
            await client.get_secret("nonexistent/secret")

    @pytest.mark.asyncio
    async def test_vault_client_get_secret_permission_denied_raises_error(self) -> None:
        """Raises error on permission denied."""
        from hvac.exceptions import InvalidPath

        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = InvalidPath(
            "permission denied"
        )
        client._client = mock_hvac_client

        with pytest.raises(VaultSecretNotFoundError):
            await client.get_secret("restricted/secret")

    @pytest.mark.asyncio
    async def test_vault_client_get_secret_with_version(self) -> None:
        """Retrieves specific version of secret."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"key": "value"}}
        }
        client._client = mock_hvac_client

        await client.get_secret("myapp/database", version=2)

        mock_hvac_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="myapp/database",
            version=2,
            mount_point="secret",
        )


class TestVaultClientSetSecret:
    """Tests for VaultClient set_secret method."""

    @pytest.mark.asyncio
    async def test_vault_client_set_secret_success(self) -> None:
        """Stores secret successfully."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        client._client = mock_hvac_client

        await client.set_secret(
            "myapp/database",
            {"username": "db_user", "password": "db_password"},
        )

        mock_hvac_client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    @pytest.mark.asyncio
    async def test_vault_client_set_secret_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        with pytest.raises(VaultConnectionError, match="Not connected"):
            await client.set_secret("myapp/database", {"key": "value"})

    @pytest.mark.asyncio
    async def test_vault_client_set_secret_permission_denied_raises_error(self) -> None:
        """Raises error on permission denied."""
        from hvac.exceptions import VaultError

        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.create_or_update_secret.side_effect = VaultError(
            "permission denied"
        )
        client._client = mock_hvac_client

        with pytest.raises(VaultPermissionError, match="Permission denied"):
            await client.set_secret("myapp/database", {"key": "value"})


class TestVaultClientDeleteSecret:
    """Tests for VaultClient delete_secret method."""

    @pytest.mark.asyncio
    async def test_vault_client_delete_secret_success(self) -> None:
        """Deletes secret successfully."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        client._client = mock_hvac_client

        await client.delete_secret("myapp/database")

        mock_hvac_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once()

    @pytest.mark.asyncio
    async def test_vault_client_delete_secret_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        with pytest.raises(VaultConnectionError, match="Not connected"):
            await client.delete_secret("myapp/database")


class TestVaultClientGetDynamicSecret:
    """Tests for VaultClient get_dynamic_secret method."""

    @pytest.mark.asyncio
    async def test_vault_client_get_dynamic_secret_success(self) -> None:
        """Retrieves dynamic secret with lease successfully."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.read.return_value = {
            "lease_id": "lease-123",
            "lease_duration": 3600,
            "renewable": True,
            "data": {
                "username": "dynamic_user",
                "password": "dynamic_password",
            },
        }
        client._client = mock_hvac_client

        lease = await client.get_dynamic_secret("database/creds/myapp")

        assert lease.lease_id == "lease-123"
        assert lease.lease_duration == 3600
        assert lease.renewable is True
        assert lease.secret_data == {
            "username": "dynamic_user",
            "password": "dynamic_password",
        }

    @pytest.mark.asyncio
    async def test_vault_client_get_dynamic_secret_not_found_raises_error(self) -> None:
        """Raises error when dynamic secret not found."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.read.return_value = None
        client._client = mock_hvac_client

        with pytest.raises(VaultSecretNotFoundError, match="Dynamic secret not found"):
            await client.get_dynamic_secret("nonexistent/path")

    @pytest.mark.asyncio
    async def test_vault_client_get_dynamic_secret_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        with pytest.raises(VaultConnectionError, match="Not connected"):
            await client.get_dynamic_secret("database/creds/myapp")


class TestVaultClientRenewLease:
    """Tests for VaultClient renew_lease method."""

    @pytest.mark.asyncio
    async def test_vault_client_renew_lease_success(self) -> None:
        """Renews lease successfully."""
        client = VaultClient()
        client._is_authenticated = True

        existing_lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
        )
        client._leases["lease-123"] = existing_lease

        mock_hvac_client = MagicMock()
        mock_hvac_client.sys.renew_lease.return_value = {
            "lease_duration": 7200,
            "renewable": True,
        }
        client._client = mock_hvac_client

        renewed_lease = await client.renew_lease("lease-123")

        assert renewed_lease.lease_duration == 7200
        assert renewed_lease.renewable is True

    @pytest.mark.asyncio
    async def test_vault_client_renew_lease_not_found_raises_error(self) -> None:
        """Raises error when lease not found."""
        client = VaultClient()
        client._is_authenticated = True
        client._client = MagicMock()

        with pytest.raises(VaultSecretNotFoundError, match="Lease not found"):
            await client.renew_lease("nonexistent-lease")

    @pytest.mark.asyncio
    async def test_vault_client_renew_lease_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        with pytest.raises(VaultConnectionError, match="Not connected"):
            await client.renew_lease("lease-123")


class TestVaultClientRevokeLease:
    """Tests for VaultClient revoke_lease method."""

    @pytest.mark.asyncio
    async def test_vault_client_revoke_lease_success(self) -> None:
        """Revokes lease successfully."""
        client = VaultClient()
        client._is_authenticated = True

        existing_lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
        )
        client._leases["lease-123"] = existing_lease

        mock_hvac_client = MagicMock()
        client._client = mock_hvac_client

        await client.revoke_lease("lease-123")

        mock_hvac_client.sys.revoke_lease.assert_called_once_with(lease_id="lease-123")
        assert "lease-123" not in client._leases

    @pytest.mark.asyncio
    async def test_vault_client_revoke_lease_not_connected(self) -> None:
        """Does nothing when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        await client.revoke_lease("lease-123")

    @pytest.mark.asyncio
    async def test_vault_client_revoke_lease_already_revoked(self) -> None:
        """Handles already revoked lease gracefully."""
        client = VaultClient()
        client._is_authenticated = True

        existing_lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
        )
        client._leases["lease-123"] = existing_lease

        mock_hvac_client = MagicMock()
        mock_hvac_client.sys.revoke_lease.side_effect = Exception("Lease already revoked")
        client._client = mock_hvac_client

        await client.revoke_lease("lease-123")

        assert "lease-123" not in client._leases


class TestVaultClientListSecrets:
    """Tests for VaultClient list_secrets method."""

    @pytest.mark.asyncio
    async def test_vault_client_list_secrets_success(self) -> None:
        """Lists secrets successfully."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["secret1", "secret2", "secret3"]}
        }
        client._client = mock_hvac_client

        result = await client.list_secrets("myapp")

        assert result == ["secret1", "secret2", "secret3"]

    @pytest.mark.asyncio
    async def test_vault_client_list_secrets_empty_path(self) -> None:
        """Lists secrets at root path."""
        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["app1", "app2"]}
        }
        client._client = mock_hvac_client

        await client.list_secrets("")

        mock_hvac_client.secrets.kv.v2.list_secrets.assert_called_once_with(
            path="",
            mount_point="secret",
        )

    @pytest.mark.asyncio
    async def test_vault_client_list_secrets_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._is_authenticated = False

        with pytest.raises(VaultConnectionError, match="Not connected"):
            await client.list_secrets("myapp")

    @pytest.mark.asyncio
    async def test_vault_client_list_secrets_invalid_path_returns_empty(self) -> None:
        """Returns empty list for invalid path."""
        from hvac.exceptions import InvalidPath

        client = VaultClient()
        client._is_authenticated = True

        mock_hvac_client = MagicMock()
        mock_hvac_client.secrets.kv.v2.list_secrets.side_effect = InvalidPath("Path not found")
        client._client = mock_hvac_client

        result = await client.list_secrets("nonexistent")

        assert result == []


class TestVaultClientHealthCheck:
    """Tests for VaultClient health_check method."""

    @pytest.mark.asyncio
    async def test_vault_client_health_check_success(self) -> None:
        """Returns health status successfully."""
        client = VaultClient()
        client._client = MagicMock()
        client._client.sys.read_health_status.return_value = {
            "initialized": True,
            "sealed": False,
            "standby": False,
        }

        result = await client.health_check()

        assert result["initialized"] is True
        assert result["sealed"] is False
        assert result["standby"] is False

    @pytest.mark.asyncio
    async def test_vault_client_health_check_not_connected_raises_error(self) -> None:
        """Raises error when not connected."""
        client = VaultClient()
        client._client = None

        with pytest.raises(VaultConnectionError, match="Vault client not initialized"):
            await client.health_check()

    @pytest.mark.asyncio
    async def test_vault_client_health_check_failure(self) -> None:
        """Handles health check failure."""
        client = VaultClient()
        client._client = MagicMock()
        client._client.sys.read_health_status.side_effect = Exception("Connection refused")

        with pytest.raises(VaultConnectionError, match="Health check failed"):
            await client.health_check()


class TestVaultClientDisconnect:
    """Tests for VaultClient disconnect method."""

    @pytest.mark.asyncio
    async def test_vault_client_disconnect_success(self) -> None:
        """Disconnects and cleans up resources."""
        client = VaultClient()
        client._is_authenticated = True
        client._token = "test-token"

        existing_lease = SecretLease(
            lease_id="lease-123",
            lease_duration=3600,
        )
        client._leases["lease-123"] = existing_lease

        mock_hvac_client = MagicMock()
        client._client = mock_hvac_client

        await client.disconnect()

        assert client._is_authenticated is False
        assert client._token is None
        assert client._leases == {}

    @pytest.mark.asyncio
    async def test_vault_client_disconnect_cancels_renewal_tasks(self) -> None:
        """Cancels pending renewal tasks."""
        client = VaultClient()
        client._is_authenticated = True

        mock_task = AsyncMock()
        client._renewal_tasks.add(mock_task)

        await client.disconnect()

        mock_task.cancel.assert_called()
        assert len(client._renewal_tasks) == 0


class TestVaultClientContextManager:
    """Tests for VaultClient async context manager."""

    @pytest.mark.asyncio
    async def test_vault_client_context_manager_entry(self) -> None:
        """Calls connect on context manager entry."""
        config = VaultConfig(url="http://localhost:8200", token="test-token")
        client = VaultClient(config=config)

        mock_hvac_client = MagicMock()
        mock_hvac_client.is_authenticated.return_value = True

        with patch(
            "securAIty.security.vault_client.hvac.Client",
            return_value=mock_hvac_client,
        ):
            async with client as c:
                assert c._is_authenticated is True

    @pytest.mark.asyncio
    async def test_vault_client_context_manager_exit(self) -> None:
        """Calls disconnect on context manager exit."""
        config = VaultConfig(url="http://localhost:8200", token="test-token")
        client = VaultClient(config=config)

        mock_hvac_client = MagicMock()
        mock_hvac_client.is_authenticated.return_value = True

        with patch(
            "securAIty.security.vault_client.hvac.Client",
            return_value=mock_hvac_client,
        ):
            async with client:
                pass

            assert client._is_authenticated is False


class TestVaultClientProperties:
    """Tests for VaultClient properties."""

    def test_vault_client_is_authenticated_false(self) -> None:
        """Returns False when not authenticated."""
        client = VaultClient()
        assert client.is_authenticated is False

    def test_vault_client_is_authenticated_true(self) -> None:
        """Returns True when authenticated."""
        client = VaultClient()
        client._is_authenticated = True
        assert client.is_authenticated is True

    def test_vault_client_token_none(self) -> None:
        """Returns None when no token."""
        client = VaultClient()
        assert client.token is None

    def test_vault_client_token_returns_token(self) -> None:
        """Returns current token."""
        client = VaultClient()
        client._token = "test-token"
        assert client.token == "test-token"


class TestVaultClientTokenRenewal:
    """Tests for VaultClient token renewal functionality."""

    @pytest.mark.asyncio
    async def test_vault_client_renew_token_success(self) -> None:
        """Renews token successfully."""
        client = VaultClient()
        client._is_authenticated = True
        client._token = "test-token"

        mock_hvac_client = MagicMock()
        mock_hvac_client.auth.token.renew_self.return_value = {
            "auth": {"lease_duration": 7200}
        }
        client._client = mock_hvac_client

        await client._renew_token()

        mock_hvac_client.auth.token.renew_self.assert_called_once()

    @pytest.mark.asyncio
    async def test_vault_client_renew_token_no_token_raises_error(self) -> None:
        """Raises error when no token to renew."""
        client = VaultClient()
        client._is_authenticated = True
        client._token = None

        with pytest.raises(VaultAuthenticationError, match="No token to renew"):
            await client._renew_token()

    @pytest.mark.asyncio
    async def test_vault_client_renew_token_failure_raises_error(self) -> None:
        """Raises error on renewal failure."""
        client = VaultClient()
        client._is_authenticated = True
        client._token = "test-token"

        mock_hvac_client = MagicMock()
        mock_hvac_client.auth.token.renew_self.side_effect = Exception("Renewal failed")
        client._client = mock_hvac_client

        with pytest.raises(VaultAuthenticationError, match="Token renewal failed"):
            await client._renew_token()

    @pytest.mark.asyncio
    async def test_vault_client_schedule_token_renewal(self) -> None:
        """Schedules token renewal task."""
        client = VaultClient()
        client._is_authenticated = True

        await client._schedule_token_renewal(3600)

        assert len(client._renewal_tasks) == 1

    @pytest.mark.asyncio
    async def test_vault_client_approle_login_success(self) -> None:
        """AppRole login succeeds."""
        client = VaultClient()
        client._client = MagicMock()
        client._client.auth.approle.login.return_value = {
            "auth": {
                "client_token": "approle-token",
                "lease_duration": 3600,
            }
        }

        await client._approle_login()

        assert client._token == "approle-token"
        assert client._is_authenticated is True

    @pytest.mark.asyncio
    async def test_vault_client_approle_login_invalid_response_raises_error(self) -> None:
        """Raises error on invalid AppRole response."""
        client = VaultClient()
        client._client = MagicMock()
        client._client.auth.approle.login.return_value = {"invalid": "response"}

        with pytest.raises(VaultAuthenticationError, match="Invalid response"):
            await client._approle_login()

    @pytest.mark.asyncio
    async def test_vault_client_approle_login_invalid_path_raises_error(self) -> None:
        """Raises error on invalid AppRole path."""
        from hvac.exceptions import InvalidPath

        client = VaultClient()
        client._client = MagicMock()
        client._client.auth.approle.login.side_effect = InvalidPath("Invalid path")

        with pytest.raises(VaultAuthenticationError, match="AppRole path invalid"):
            await client._approle_login()
