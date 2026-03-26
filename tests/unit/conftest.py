"""
Shared fixtures for unit tests.

Provides common test data, mocks, and utilities for all unit tests.
"""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator, Generator, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from securAIty.security.exceptions import (
    SecurityError,
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
)
from securAIty.events.schema import (
    SecurityEvent,
    EventType,
    Severity,
    EventContext,
)
from securAIty.agents.base import (
    BaseAgent,
    AgentMetadata,
    AgentCapability,
    TaskRequest,
    TaskResult,
    HealthStatus,
    TaskPriority,
)


@pytest.fixture(scope="session")
def event_loop_policy() -> asyncio.AbstractEventLoopPolicy:
    """Return event loop policy for async tests."""
    return asyncio.get_event_loop_policy()


@pytest.fixture
def sample_user_id() -> str:
    """Return sample user ID for tests."""
    return "test-user-12345"


@pytest.fixture
def sample_session_id() -> str:
    """Return sample session ID for tests."""
    return "session-abc-def-123"


@pytest.fixture
def sample_correlation_id() -> str:
    """Return sample correlation ID for tests."""
    return "corr-xyz-789-456"


@pytest.fixture
def sample_password() -> str:
    """Return sample password for tests."""
    return "SecureP@ssw0rd123!"


@pytest.fixture
def sample_email() -> str:
    """Return sample email for tests."""
    return "test.user @example.com"


@pytest.fixture
def sample_username() -> str:
    """Return sample username for tests."""
    return "testuser123"


@pytest.fixture
def sample_ip_address() -> str:
    """Return sample IP address for tests."""
    return "192.168.1.100"


@pytest.fixture
def sample_roles() -> list[str]:
    """Return sample roles for tests."""
    return ["admin", "security_analyst", "auditor"]


@pytest.fixture
def sample_permissions() -> list[str]:
    """Return sample permissions for tests."""
    return ["read:events", "write:events", "delete:incidents"]


@pytest.fixture
def rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate RSA keypair for tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def rsa_private_key_pem(rsa_keypair) -> bytes:
    """Return PEM-encoded RSA private key."""
    private_key, _ = rsa_keypair
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def rsa_public_key_pem(rsa_keypair) -> bytes:
    """Return PEM-encoded RSA public key."""
    _, public_key = rsa_keypair
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture
def encrypted_rsa_private_key_pem(rsa_keypair, sample_password) -> bytes:
    """Return password-encrypted PEM-encoded RSA private key."""
    private_key, _ = rsa_keypair
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            sample_password.encode("utf-8")
        ),
    )


@pytest.fixture
def sample_aes_key() -> bytes:
    """Return sample 32-byte AES key."""
    import secrets
    return secrets.token_bytes(32)


@pytest.fixture
def sample_nonce() -> bytes:
    """Return sample 12-byte nonce."""
    import secrets
    return secrets.token_bytes(12)


@pytest.fixture
def sample_plaintext() -> bytes:
    """Return sample plaintext data."""
    return b"Sensitive data to encrypt"


@pytest.fixture
def sample_hash() -> str:
    """Return sample SHA-256 hash."""
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture
def sample_jwt_token() -> str:
    """Return sample JWT token for tests."""
    header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
    payload = "eyJzdWIiOiJ0ZXN0LXVzZXItMTIzNDUiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9"
    signature = "fake_signature_for_testing_purposes_only"
    return f"{header}.{payload}.{signature}"


@pytest.fixture
def event_context(sample_user_id, sample_session_id, sample_ip_address) -> EventContext:
    """Create sample event context."""
    return EventContext(
        user_id=sample_user_id,
        session_id=sample_session_id,
        ip_address=sample_ip_address,
        environment="test",
        custom={"test_key": "test_value"},
    )


@pytest.fixture
def security_event(sample_user_id, event_context) -> SecurityEvent:
    """Create sample security event."""
    return SecurityEvent(
        event_id="test-event-12345",
        source="test-agent",
        event_type=EventType.SECURITY_SCAN_INITIATED,
        severity=Severity.INFO,
        correlation_id="test-correlation-67890",
        payload={"scan_type": "vulnerability", "target": "web-app"},
        context=event_context,
    )


@pytest.fixture
def threat_detected_event(event_context) -> SecurityEvent:
    """Create sample threat detected event."""
    return SecurityEvent(
        event_id="threat-event-001",
        source="threat-detector",
        event_type=EventType.THREAT_DETECTED,
        severity=Severity.HIGH,
        correlation_id="threat-correlation-001",
        payload={
            "threat_type": "malware",
            "confidence": 0.95,
            "indicators": ["suspicious_process.exe", "malicious.dll"],
        },
        context=event_context,
    )


@pytest.fixture
def policy_violation_event(event_context) -> SecurityEvent:
    """Create sample policy violation event."""
    return SecurityEvent(
        event_id="policy-violation-001",
        source="policy-engine",
        event_type=EventType.POLICY_VIOLATION,
        severity=Severity.MEDIUM,
        correlation_id="policy-correlation-001",
        payload={
            "policy_id": "POL-001",
            "violation_type": "unauthorized_access",
            "resource": "/api/admin/users",
        },
        context=event_context,
    )


@pytest.fixture
def agent_capability() -> AgentCapability:
    """Create sample agent capability."""
    return AgentCapability(
        name="scan_vulnerabilities",
        description="Scan system for known vulnerabilities",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string", "enum": ["quick", "full", "deep"]},
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "vulnerabilities": {"type": "array"},
                "scan_duration": {"type": "number"},
            },
        },
        timeout=300.0,
    )


@pytest.fixture
def agent_metadata(agent_capability) -> AgentMetadata:
    """Create sample agent metadata."""
    metadata = AgentMetadata(
        agent_id="test-agent-001",
        agent_type="security_scanner",
        version="1.0.0",
        health_status=HealthStatus.HEALTHY,
    )
    metadata.add_capability(agent_capability)
    return metadata


@pytest.fixture
def task_request() -> TaskRequest:
    """Create sample task request."""
    return TaskRequest(
        task_id="task-001",
        capability="scan_vulnerabilities",
        input_data={"target": "192.168.1.1", "scan_type": "quick"},
        priority=TaskPriority.NORMAL,
    )


@pytest.fixture
def task_result_success() -> TaskResult:
    """Create sample successful task result."""
    return TaskResult(
        task_id="task-001",
        success=True,
        output_data={
            "vulnerabilities": [],
            "scan_duration": 15.5,
            "status": "completed",
        },
        execution_time_ms=15500.0,
        evidence=[{"type": "scan_log", "data": "scan completed successfully"}],
    )


@pytest.fixture
def task_result_failure() -> TaskResult:
    """Create sample failed task result."""
    return TaskResult(
        task_id="task-002",
        success=False,
        error_message="Target unreachable - connection timeout",
        execution_time_ms=30000.0,
    )


@pytest.fixture
def mock_vault_config() -> dict[str, Any]:
    """Return mock Vault configuration."""
    return {
        "url": "http://localhost:8200",
        "token": "test-vault-token",
        "approle_role_id": "test-role-id",
        "approle_secret_id": "test-secret-id",
        "namespace": None,
        "verify": True,
        "timeout": 30,
    }


@pytest.fixture
def mock_vault_secret_data() -> dict[str, Any]:
    """Return mock Vault secret data."""
    return {
        "username": "db_user",
        "password": "db_password_123",
        "host": "db.example.com",
        "port": 5432,
    }


@pytest.fixture
def mock_vault_lease() -> dict[str, Any]:
    """Return mock Vault lease information."""
    return {
        "lease_id": "lease-abc-123",
        "lease_duration": 3600,
        "renewable": True,
    }


@pytest.fixture
def mock_nats_config() -> dict[str, Any]:
    """Return mock NATS configuration."""
    return {
        "servers": ["nats://localhost:4222"],
        "cluster_id": "test-cluster",
        "client_id": "test-client",
        "queue_group": "test-queue",
    }


@pytest.fixture
def mock_async_session() -> AsyncMock:
    """Create mock async database session."""
    session = AsyncMock()
    session.get = AsyncMock()
    session.execute = AsyncMock()
    session.add = AsyncMock()
    session.add_all = AsyncMock()
    session.delete = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    return session


@pytest.fixture
def mock_nats_client() -> AsyncMock:
    """Create mock NATS client."""
    client = AsyncMock()
    client.publish = AsyncMock()
    client.subscribe = AsyncMock()
    client.request = AsyncMock()
    client.close = AsyncMock()
    client.drain = AsyncMock()
    client.is_connected = True
    client.connected_url = MagicMock()
    client.connected_url.netloc = "localhost:4222"
    return client


@pytest.fixture
def mock_vault_client() -> AsyncMock:
    """Create mock Vault client."""
    client = AsyncMock()
    client.is_authenticated = True
    client.token = "test-token"
    client.secrets.kv.v2.read_secret_version = AsyncMock()
    client.secrets.kv.v2.create_or_update_secret = AsyncMock()
    client.secrets.kv.v2.delete_metadata_and_all_versions = AsyncMock()
    client.secrets.kv.v2.list_secrets = AsyncMock()
    client.auth.approle.login = AsyncMock()
    client.auth.token.renew_self = AsyncMock()
    client.read = AsyncMock()
    client.sys.renew_lease = AsyncMock()
    client.sys.revoke_lease = AsyncMock()
    client.sys.read_health_status = AsyncMock()
    return client


@pytest.fixture
def mock_hvac_client(mock_vault_client) -> Generator[AsyncMock, None, None]:
    """Mock hvac.Client for Vault tests."""
    with patch("securAIty.security.vault_client.hvac.Client", return_value=mock_vault_client):
        yield mock_vault_client


@pytest.fixture
def mock_nats_connect() -> Generator[AsyncMock, None, None]:
    """Mock NATS connect function."""
    with patch("securAIty.events.bus.nats.connect", return_value=AsyncMock()) as mock_connect:
        yield mock_connect


@pytest.fixture
def current_timestamp() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


@pytest.fixture
def future_timestamp() -> datetime:
    """Return timestamp 1 hour in the future."""
    return datetime.now(timezone.utc) + timedelta(hours=1)


@pytest.fixture
def past_timestamp() -> datetime:
    """Return timestamp 1 hour in the past."""
    return datetime.now(timezone.utc) - timedelta(hours=1)


@pytest.fixture
def expired_timestamp() -> datetime:
    """Return timestamp 1 day in the past (expired)."""
    return datetime.now(timezone.utc) - timedelta(days=1)


@pytest_asyncio.fixture
async def cleanup_resources():
    """Fixture for resource cleanup after tests."""
    resources = []
    yield resources
    for resource in resources:
        if asyncio.iscoroutinefunction(resource):
            await resource()
        elif callable(resource):
            resource()


@pytest.fixture
def sample_sql_injection_payloads() -> list[str]:
    """Return common SQL injection payloads for testing."""
    return [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1; DELETE FROM users",
        "admin'--",
        "1 UNION SELECT * FROM users",
        "1' AND '1'='1",
    ]


@pytest.fixture
def sample_xss_payloads() -> list[str]:
    """Return common XSS payloads for testing."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'>",
    ]


@pytest.fixture
def sample_valid_inputs() -> list[str]:
    """Return sample valid inputs for testing."""
    return [
        "normal text input",
        "user123",
        "test @example.com",
        "192.168.1.1",
        "https://example.com/path?query=value",
    ]


@pytest.fixture
def exception_hierarchy() -> dict[type[Exception], list[type[Exception]]]:
    """Return security exception hierarchy for testing."""
    return {
        SecurityError: [
            CryptoError,
            VaultError,
            JWTError,
            SecurityValidationError,
        ],
        CryptoError: [
            EncryptionError,
            DecryptionError,
            KeyGenerationError,
            HashError,
            SignatureError,
        ],
        VaultError: [
            VaultConnectionError,
            VaultAuthenticationError,
            VaultSecretNotFoundError,
            VaultPermissionError,
            VaultLeaseError,
        ],
        JWTError: [
            JWTDecodeError,
            JWTExpiredError,
            JWTInvalidClaimsError,
            JWTRevokedError,
        ],
    }


class MockBaseAgent(BaseAgent):
    """Mock agent for testing."""

    def __init__(
        self,
        agent_type: str = "mock",
        version: str = "1.0.0",
        should_fail_initialize: bool = False,
        should_fail_execute: bool = False,
        should_fail_health_check: bool = False,
    ) -> None:
        super().__init__(agent_type=agent_type, version=version)
        self.should_fail_initialize = should_fail_initialize
        self.should_fail_execute = should_fail_execute
        self.should_fail_health_check = should_fail_health_check
        self._execute_calls = []
        self._shutdown_called = False

    async def initialize(self) -> None:
        """Initialize mock agent."""
        if self.should_fail_initialize:
            raise RuntimeError("Mock initialization failure")
        self._initialized = True
        self._update_health_status(HealthStatus.HEALTHY)

    async def execute(self, request: TaskRequest) -> TaskResult:
        """Execute mock task."""
        self._execute_calls.append(request)

        if self.should_fail_execute:
            return TaskResult.failure(
                task_id=request.task_id,
                error_message="Mock execution failure",
            )

        return TaskResult.success(
            task_id=request.task_id,
            output_data={"result": f"Executed {request.capability}"},
            execution_time_ms=100.0,
        )

    async def health_check(self) -> HealthStatus:
        """Check mock agent health."""
        if self.should_fail_health_check:
            self._update_health_status(HealthStatus.UNHEALTHY)
            return HealthStatus.UNHEALTHY
        return HealthStatus.HEALTHY

    async def shutdown(self) -> None:
        """Shutdown mock agent."""
        self._shutdown_called = True
        self._initialized = False

    @property
    def execute_calls(self) -> list[TaskRequest]:
        """Return list of execute calls."""
        return self._execute_calls

    @property
    def shutdown_called(self) -> bool:
        """Return whether shutdown was called."""
        return self._shutdown_called


@pytest.fixture
def mock_agent_class() -> type[MockBaseAgent]:
    """Return mock agent class for testing."""
    return MockBaseAgent


@pytest.fixture
def healthy_mock_agent() -> MockBaseAgent:
    """Create healthy mock agent."""
    return MockBaseAgent()


@pytest.fixture
def unhealthy_mock_agent() -> MockBaseAgent:
    """Create unhealthy mock agent."""
    return MockBaseAgent(should_fail_health_check=True)


@pytest.fixture
def failing_mock_agent() -> MockBaseAgent:
    """Create failing mock agent."""
    return MockBaseAgent(should_fail_execute=True)
