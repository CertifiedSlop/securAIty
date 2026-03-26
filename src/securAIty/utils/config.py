"""
Configuration Management

Centralized configuration management for securAIty components
with environment variable support and validation.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class NATSConfig:
    """
    NATS server configuration.

    Attributes:
        servers: List of NATS server URLs
        queue_group: Consumer group name
        max_reconnect_attempts: Maximum reconnection attempts
        reconnect_delay: Delay between reconnection attempts
        connection_timeout: Connection timeout
        jetstream_enabled: Enable JetStream persistence
        jetstream_stream: JetStream stream name
    """

    servers: list[str] = field(default_factory=lambda: ["nats://localhost:4222"])
    queue_group: str = "securAIty_events"
    max_reconnect_attempts: int = 10
    reconnect_delay: float = 2.0
    connection_timeout: float = 5.0
    jetstream_enabled: bool = True
    jetstream_stream: str = "SECURITY_EVENTS"


@dataclass
class AgentConfig:
    """
    Agent-specific configuration.

    Attributes:
        max_concurrent_tasks: Maximum parallel tasks per agent
        task_timeout: Default task timeout in seconds
        max_retries: Maximum retry attempts
        enable_logging: Enable agent logging
        log_level: Logging level
    """

    max_concurrent_tasks: int = 10
    task_timeout: float = 300.0
    max_retries: int = 3
    enable_logging: bool = True
    log_level: str = "INFO"


@dataclass
class OrchestratorConfig:
    """
    Orchestrator configuration.

    Attributes:
        orchestrator_id: Unique orchestrator identifier
        pattern: Orchestration pattern (sequential, concurrent, etc.)
        max_concurrent_tasks: Maximum parallel workflow tasks
        task_timeout: Default task timeout
        enable_policy_enforcement: Enable policy checks
        enable_state_persistence: Enable checkpointing
        checkpoint_interval: Checkpoint frequency
    """

    orchestrator_id: str = "orchestrator_001"
    pattern: str = "sequential"
    max_concurrent_tasks: int = 10
    task_timeout: float = 300.0
    enable_policy_enforcement: bool = True
    enable_state_persistence: bool = True
    checkpoint_interval: int = 10


@dataclass
class PolicyConfig:
    """
    Policy engine configuration.

    Attributes:
        default_effect: Default policy effect (allow/deny)
        evaluation_timeout: Policy evaluation timeout
        policies_path: Path to policy definitions
    """

    default_effect: str = "allow"
    evaluation_timeout: float = 5.0
    policies_path: str = "./config/policies"


@dataclass
class QwenConfig:
    """
    Qwen integration configuration.

    Attributes:
        api_endpoint: Qwen API endpoint
        api_key: API authentication key
        model: Model identifier
        max_tokens: Maximum response tokens
        temperature: Response temperature
        timeout: Request timeout
    """

    api_endpoint: str = "http://localhost:11434"
    api_key: Optional[str] = None
    model: str = "qwen-72b"
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0


@dataclass
class StorageConfig:
    """
    Storage configuration.

    Attributes:
        checkpoint_path: Path for state checkpoints
        log_path: Path for log files
        data_path: Path for data storage
        retention_days: Data retention period
    """

    checkpoint_path: str = "./checkpoints"
    log_path: str = "./logs"
    data_path: str = "./data"
    retention_days: int = 30


@dataclass
class SecurityConfig:
    """
    Security configuration.

    Attributes:
        encryption_enabled: Enable data encryption
        audit_logging: Enable audit logging
        api_key_header: API key header name
        cors_origins: Allowed CORS origins
    """

    encryption_enabled: bool = True
    audit_logging: bool = True
    api_key_header: str = "X-API-Key"
    cors_origins: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class SecurAItyConfig:
    """
    Main securAIty configuration container.

    Attributes:
        environment: Deployment environment
        debug: Enable debug mode
        nats: NATS configuration
        agent: Agent configuration
        orchestrator: Orchestrator configuration
        policy: Policy configuration
        qwen: Qwen integration configuration
        storage: Storage configuration
        security: Security configuration
    """

    environment: str = "development"
    debug: bool = False
    nats: NATSConfig = field(default_factory=NATSConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    qwen: QwenConfig = field(default_factory=QwenConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            Configuration dictionary
        """
        return {
            "environment": self.environment,
            "debug": self.debug,
            "nats": {
                "servers": self.nats.servers,
                "queue_group": self.nats.queue_group,
                "max_reconnect_attempts": self.nats.max_reconnect_attempts,
                "reconnect_delay": self.nats.reconnect_delay,
                "connection_timeout": self.nats.connection_timeout,
                "jetstream_enabled": self.nats.jetstream_enabled,
                "jetstream_stream": self.nats.jetstream_stream,
            },
            "agent": {
                "max_concurrent_tasks": self.agent.max_concurrent_tasks,
                "task_timeout": self.agent.task_timeout,
                "max_retries": self.agent.max_retries,
                "enable_logging": self.agent.enable_logging,
                "log_level": self.agent.log_level,
            },
            "orchestrator": {
                "orchestrator_id": self.orchestrator.orchestrator_id,
                "pattern": self.orchestrator.pattern,
                "max_concurrent_tasks": self.orchestrator.max_concurrent_tasks,
                "task_timeout": self.orchestrator.task_timeout,
                "enable_policy_enforcement": self.orchestrator.enable_policy_enforcement,
                "enable_state_persistence": self.orchestrator.enable_state_persistence,
                "checkpoint_interval": self.orchestrator.checkpoint_interval,
            },
            "policy": {
                "default_effect": self.policy.default_effect,
                "evaluation_timeout": self.policy.evaluation_timeout,
                "policies_path": self.policy.policies_path,
            },
            "qwen": {
                "api_endpoint": self.qwen.api_endpoint,
                "api_key": self.qwen.api_key,
                "model": self.qwen.model,
                "max_tokens": self.qwen.max_tokens,
                "temperature": self.qwen.temperature,
                "timeout": self.qwen.timeout,
            },
            "storage": {
                "checkpoint_path": self.storage.checkpoint_path,
                "log_path": self.storage.log_path,
                "data_path": self.storage.data_path,
                "retention_days": self.storage.retention_days,
            },
            "security": {
                "encryption_enabled": self.security.encryption_enabled,
                "audit_logging": self.security.audit_logging,
                "api_key_header": self.security.api_key_header,
                "cors_origins": self.security.cors_origins,
            },
        }


class ConfigManager:
    """
    Configuration manager for securAIty.

    Loads configuration from files, environment variables,
    and provides validation and access methods.

    Attributes:
        config: Current configuration
        config_path: Path to configuration file
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize configuration manager.

        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path or self._find_config_file()
        self.config = SecurAItyConfig()

        if self.config_path:
            self._load_from_file()

        self._load_from_env()
        self._ensure_directories()

    def _find_config_file(self) -> Optional[str]:
        """
        Find configuration file in standard locations.

        Returns:
            Path to config file or None
        """
        possible_paths = [
            Path("./config/securAIty.yaml"),
            Path("./config/securAIty.yml"),
            Path("/etc/securAIty/config.yaml"),
            Path.home() / ".securAIty" / "config.yaml",
        ]

        for path in possible_paths:
            if path.exists():
                return str(path)

        return None

    def _load_from_file(self) -> None:
        """
        Load configuration from YAML file.

        Raises:
            FileNotFoundError: If config file not found
        """
        if not self.config_path:
            return

        path = Path(self.config_path)

        if not path.exists():
            return

        with open(path, "r") as f:
            file_config = yaml.safe_load(f) or {}

        self._apply_dict_config(file_config)

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        env_mapping = {
            "SECURAITY_ENV": ("environment", str),
            "SECURAITY_DEBUG": ("debug", lambda x: x.lower() == "true"),
            "SECURAITY_NATS_SERVERS": ("nats_servers", lambda x: x.split(",")),
            "SECURAITY_NATS_QUEUE_GROUP": ("nats_queue_group", str),
            "SECURAITY_ORCHESTRATOR_PATTERN": ("orchestrator_pattern", str),
            "SECURAITY_QWEN_ENDPOINT": ("qwen_endpoint", str),
            "SECURAITY_QWEN_MODEL": ("qwen_model", str),
            "SECURAITY_QWEN_API_KEY": ("qwen_api_key", str),
            "SECURAITY_CHECKPOINT_PATH": ("checkpoint_path", str),
            "SECURAITY_LOG_LEVEL": ("log_level", str),
        }

        for env_var, (config_key, converter) in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                self._set_config_value(config_key, converter(value))

    def _apply_dict_config(self, config_dict: dict[str, Any]) -> None:
        """
        Apply dictionary configuration.

        Args:
            config_dict: Configuration dictionary
        """
        if "environment" in config_dict:
            self.config.environment = config_dict["environment"]

        if "debug" in config_dict:
            self.config.debug = config_dict["debug"]

        if "nats" in config_dict:
            nats_config = config_dict["nats"]
            if "servers" in nats_config:
                self.config.nats.servers = nats_config["servers"]
            if "queue_group" in nats_config:
                self.config.nats.queue_group = nats_config["queue_group"]
            if "jetstream_enabled" in nats_config:
                self.config.nats.jetstream_enabled = nats_config["jetstream_enabled"]

        if "orchestrator" in config_dict:
            orch_config = config_dict["orchestrator"]
            if "pattern" in orch_config:
                self.config.orchestrator.pattern = orch_config["pattern"]
            if "orchestrator_id" in orch_config:
                self.config.orchestrator.orchestrator_id = orch_config["orchestrator_id"]

        if "qwen" in config_dict:
            qwen_config = config_dict["qwen"]
            if "api_endpoint" in qwen_config:
                self.config.qwen.api_endpoint = qwen_config["api_endpoint"]
            if "model" in qwen_config:
                self.config.qwen.model = qwen_config["model"]
            if "api_key" in qwen_config:
                self.config.qwen.api_key = qwen_config["api_key"]

        if "storage" in config_dict:
            storage_config = config_dict["storage"]
            if "checkpoint_path" in storage_config:
                self.config.storage.checkpoint_path = storage_config["checkpoint_path"]

    def _set_config_value(self, key: str, value: Any) -> None:
        """
        Set configuration value by dotted key path.

        Args:
            key: Dotted key path (e.g., "nats.servers")
            value: Value to set
        """
        parts = key.split("_")

        if parts[0] == "nats":
            if len(parts) > 1:
                attr = "_".join(parts[1:])
                if hasattr(self.config.nats, attr):
                    setattr(self.config.nats, attr, value)

        elif parts[0] == "orchestrator":
            if len(parts) > 1:
                attr = "_".join(parts[1:])
                if hasattr(self.config.orchestrator, attr):
                    setattr(self.config.orchestrator, attr, value)

        elif parts[0] == "qwen":
            if len(parts) > 1:
                attr = "_".join(parts[1:])
                if hasattr(self.config.qwen, attr):
                    setattr(self.config.qwen, attr, value)

        elif parts[0] == "storage":
            if len(parts) > 1:
                attr = "_".join(parts[1:])
                if hasattr(self.config.storage, attr):
                    setattr(self.config.storage, attr, value)

        elif parts[0] == "agent":
            if len(parts) > 1:
                attr = "_".join(parts[1:])
                if hasattr(self.config.agent, attr):
                    setattr(self.config.agent, attr, value)

        elif hasattr(self.config, parts[0]):
            setattr(self.config, parts[0], value)

    def _ensure_directories(self) -> None:
        """Create necessary directories."""
        directories = [
            self.config.storage.checkpoint_path,
            self.config.storage.log_path,
            self.config.storage.data_path,
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def save(self, path: Optional[str] = None) -> None:
        """
        Save configuration to file.

        Args:
            path: Optional path to save to
        """
        save_path = path or self.config_path or "./config/securAIty.yaml"

        Path(save_path).parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w") as f:
            yaml.dump(self.config.to_dict(), f, default_flow_style=False)

    def get_nats_config(self) -> NATSConfig:
        """Get NATS configuration."""
        return self.config.nats

    def get_orchestrator_config(self) -> OrchestratorConfig:
        """Get orchestrator configuration."""
        return self.config.orchestrator

    def get_qwen_config(self) -> QwenConfig:
        """Get Qwen configuration."""
        return self.config.qwen

    def get_policy_config(self) -> PolicyConfig:
        """Get policy configuration."""
        return self.config.policy

    def is_debug(self) -> bool:
        """Check if debug mode is enabled."""
        return self.config.debug

    def is_production(self) -> bool:
        """Check if running in production."""
        return self.config.environment == "production"


_config_manager: Optional[ConfigManager] = None


def get_config(config_path: Optional[str] = None) -> ConfigManager:
    """
    Get or create global configuration manager.

    Args:
        config_path: Optional configuration file path

    Returns:
        Configuration manager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


def reload_config(config_path: Optional[str] = None) -> ConfigManager:
    """
    Reload configuration from file.

    Args:
        config_path: Optional configuration file path

    Returns:
        Reloaded configuration manager
    """
    global _config_manager
    _config_manager = ConfigManager(config_path)
    return _config_manager
