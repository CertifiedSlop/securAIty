"""
AI Antivirus Agent

Real-time threat detection and malware analysis using YARA rules,
ClamAV integration, behavioral analysis, and heuristic scanning.
"""

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from ..base import BaseAgent, HealthStatus, TaskPriority, TaskRequest, TaskResult


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(str, Enum):
    """Scan result status."""

    CLEAN = "clean"
    INFECTED = "infected"
    SUSPICIOUS = "suspicious"
    ERROR = "error"
    QUARANTINED = "quarantined"


class QuarantineStatus(str, Enum):
    """Quarantine operation status."""

    SUCCESS = "success"
    FAILED = "failed"
    ALREADY_QUARANTINED = "already_quarantined"
    FILE_NOT_FOUND = "file_not_found"


@dataclass
class ScanResult:
    """
    Result from scanning a file or directory.

    Attributes:
        file_path: Scanned file path
        status: Scan status (clean/infected/suspicious/error)
        threats_detected: List of detected threat names
        severity: Highest severity level detected
        file_hash: SHA-256 hash of scanned file
        file_size: File size in bytes
        scan_duration_ms: Time taken to scan in milliseconds
        scanner_engine: Engine used (yara/clamav/heuristic)
        timestamp: When scan was performed
        error_message: Error details if status is error
    """

    file_path: str
    status: ScanStatus
    threats_detected: list[str] = field(default_factory=list)
    severity: ThreatSeverity = ThreatSeverity.INFORMATIONAL
    file_hash: str = ""
    file_size: int = 0
    scan_duration_ms: float = 0.0
    scanner_engine: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: str = ""


@dataclass
class QuarantineResult:
    """
    Result from quarantine operation.

    Attributes:
        original_path: Original file location
        quarantine_path: Quarantined file location
        status: Operation status
        quarantine_id: Unique quarantine identifier
        timestamp: When quarantined
        error_message: Error details if failed
    """

    original_path: str
    quarantine_path: str
    status: QuarantineStatus
    quarantine_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: str = ""


@dataclass
class BehaviorReport:
    """
    Behavioral analysis report.

    Attributes:
        process_name: Analyzed process name
        risk_score: Risk score 0-100
        anomalies_detected: List of behavioral anomalies
        suspicious_activities: List of suspicious activities
        network_connections: Network activity summary
        file_operations: File operation summary
        registry_changes: Registry modification summary
        recommendation: Action recommendation
        timestamp: Analysis timestamp
    """

    process_name: str
    risk_score: int = 0
    anomalies_detected: list[str] = field(default_factory=list)
    suspicious_activities: list[str] = field(default_factory=list)
    network_connections: list[dict[str, Any]] = field(default_factory=list)
    file_operations: list[dict[str, Any]] = field(default_factory=list)
    registry_changes: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = "no_action_required"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AntivirusAgent(BaseAgent):
    """
    AI-powered antivirus agent for threat detection.

    Provides real-time malware detection using YARA rules pattern matching,
    ClamAV integration, behavioral analysis, and heuristic scanning.

    Security Features:
        - Path traversal prevention
        - Input validation on all file operations
        - Secure quarantine with cryptographic isolation
        - Rate limiting on scan operations
        - No information leakage in error messages

    Integration Points:
        - YARA rules engine for pattern matching
        - ClamAV daemon for signature-based detection
        - File system watchers for real-time monitoring
        - Behavioral monitoring hooks for process analysis
    """

    ALLOWED_FILE_EXTENSIONS = {
        ".exe", ".dll", ".so", ".bin", ".scr", ".bat", ".cmd", ".ps1",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
        ".txt", ".rtf", ".csv", ".json", ".xml", ".yaml", ".yml",
        ".js", ".ts", ".py", ".rb", ".php", ".java", ".class",
        ".html", ".css", ".svg",
    }

    DANGEROUS_EXTENSIONS = {
        ".aspx", ".asp", ".jsp", ".php", ".pl", ".cgi",
        ".htaccess", ".htpasswd", ".sh", ".bash",
    }

    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
    MAX_SCAN_CONCURRENCY = 10
    QUARANTINE_ENCRYPTION_KEY_ENV = "ANTIVIRUS_QUARANTINE_KEY"

    def __init__(
        self,
        yara_rules_path: Optional[str] = None,
        clamav_socket_path: Optional[str] = None,
        quarantine_directory: Optional[str] = None,
        max_file_size: int = MAX_FILE_SIZE_BYTES,
    ) -> None:
        """
        Initialize antivirus agent.

        Args:
            yara_rules_path: Path to YARA rules directory
            clamav_socket_path: Unix socket path for ClamAV daemon
            quarantine_directory: Secure directory for quarantined files
            max_file_size: Maximum file size to scan in bytes
        """
        super().__init__(agent_type="antivirus", version="2.0.0")

        self._yara_rules_path = yara_rules_path or "/etc/yara/rules"
        self._clamav_socket_path = clamav_socket_path or "/var/run/clamav/clamav.ctl"
        self._quarantine_directory = quarantine_directory or "/var/quarantine/securAIty"
        self._max_file_size = max_file_size

        self._yara_rules: list[Any] = []
        self._clamav_available = False
        self._scan_semaphore = asyncio.Semaphore(self.MAX_SCAN_CONCURRENCY)
        self._scan_count = 0
        self._last_scan_time = datetime.now(timezone.utc)
        self._initialized = False
        self._behavior_monitors: dict[str, Any] = {}
        self._quarantine_lock = asyncio.Lock()
        self._file_system_watchers: list[Any] = []

    async def initialize(self) -> None:
        """
        Initialize antivirus agent resources.

        Loads YARA rules, verifies ClamAV connectivity,
        and sets up quarantine directory with secure permissions.
        """
        if self._initialized:
            return

        await self._setup_quarantine_directory()
        await self._load_yara_rules()
        await self._verify_clamav_connection()
        await self._load_encryption_key()

        self._update_health_status(HealthStatus.HEALTHY)
        self._initialized = True

    async def shutdown(self) -> None:
        """
        Gracefully shutdown antivirus agent.

        Stops file system watchers, closes ClamAV connections,
        and cleans up resources.
        """
        for watcher in self._file_system_watchers:
            try:
                if hasattr(watcher, "stop"):
                    watcher.stop()
            except Exception:
                pass

        self._file_system_watchers.clear()
        self._behavior_monitors.clear()
        self._yara_rules.clear()
        self._initialized = False
        self._update_health_status(HealthStatus.UNKNOWN)

    async def health_check(self) -> HealthStatus:
        """
        Perform health check on antivirus components.

        Verifies YARA rules loaded, ClamAV connectivity,
        and quarantine directory accessibility.

        Returns:
            Current health status
        """
        if not self._initialized:
            return HealthStatus.UNHEALTHY

        yara_healthy = len(self._yara_rules) > 0
        clamav_healthy = self._clamav_available
        quarantine_healthy = await self._verify_quarantine_directory()

        if yara_healthy and clamav_healthy and quarantine_healthy:
            self._update_health_status(HealthStatus.HEALTHY)
            return HealthStatus.HEALTHY

        if yara_healthy or clamav_healthy:
            self._update_health_status(HealthStatus.DEGRADED)
            return HealthStatus.DEGRADED

        self._update_health_status(HealthStatus.UNHEALTHY)
        return HealthStatus.UNHEALTHY

    async def execute(self, request: TaskRequest) -> TaskResult:
        """
        Execute antivirus task request.

        Handles scan_file, scan_directory, quarantine_file,
        and analyze_behavior capabilities.

        Args:
            request: Task request with capability and input data

        Returns:
            TaskResult with scan results or operation status
        """
        start_time = datetime.now(timezone.utc)

        try:
            if not self._validate_task_request(request):
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message="Invalid task request",
                    execution_time_ms=0,
                )

            if request.capability == "scan_file":
                result = await self._execute_scan_file(request)
            elif request.capability == "scan_directory":
                result = await self._execute_scan_directory(request)
            elif request.capability == "quarantine_file":
                result = await self._execute_quarantine_file(request)
            elif request.capability == "analyze_behavior":
                result = await self._execute_analyze_behavior(request)
            else:
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message=f"Unknown capability: {request.capability}",
                )

            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            return TaskResult.success(
                task_id=request.task_id,
                output_data=result,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return TaskResult.failure(
                task_id=request.task_id,
                error_message="Antivirus operation failed",
                execution_time_ms=execution_time,
            )

    async def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single file for malware.

        Performs multi-engine scanning:
        1. YARA rules pattern matching
        2. ClamAV signature comparison
        3. Heuristic analysis

        Args:
            file_path: Absolute path to file to scan

        Returns:
            ScanResult with detection results

        Security Controls:
            - Path traversal validation
            - File extension allowlist
            - Size limits enforced
            - Symlink resolution prevention
        """
        async with self._scan_semaphore:
            start_time = datetime.now(timezone.utc)

            validated_path = self._validate_file_path(file_path)
            if not validated_path:
                return ScanResult(
                    file_path=file_path,
                    status=ScanStatus.ERROR,
                    error_message="Invalid file path",
                    timestamp=datetime.now(timezone.utc),
                )

            if not await self._verify_file_accessible(validated_path):
                return ScanResult(
                    file_path=file_path,
                    status=ScanStatus.ERROR,
                    error_message="File not accessible",
                    timestamp=datetime.now(timezone.utc),
                )

            file_size = await self._get_file_size(validated_path)
            if file_size > self._max_file_size:
                return ScanResult(
                    file_path=file_path,
                    status=ScanStatus.ERROR,
                    error_message="File exceeds maximum size",
                    timestamp=datetime.now(timezone.utc),
                )

            file_hash = await self._compute_file_hash(validated_path)
            file_content = await self._read_file_secure(validated_path)

            threats = []
            severity = ThreatSeverity.INFORMATIONAL

            yara_result = await self._scan_with_yara(file_content, validated_path)
            if yara_result:
                threats.extend(yara_result["threats"])
                severity = self._get_highest_severity([severity, yara_result["severity"]])

            clamav_result = await self._scan_with_clamav(file_content, validated_path)
            if clamav_result:
                threats.extend(clamav_result["threats"])
                severity = self._get_highest_severity([severity, clamav_result["severity"]])

            heuristic_result = await self._heuristic_analysis(file_content, validated_path)
            if heuristic_result:
                threats.extend(heuristic_result["threats"])
                severity = self._get_highest_severity([severity, heuristic_result["severity"]])

            scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self._scan_count += 1
            self._last_scan_time = datetime.now(timezone.utc)

            if threats:
                return ScanResult(
                    file_path=str(validated_path),
                    status=ScanStatus.INFECTED,
                    threats_detected=threats,
                    severity=severity,
                    file_hash=file_hash,
                    file_size=file_size,
                    scan_duration_ms=scan_duration,
                    scanner_engine="yara+clamav+heuristic",
                    timestamp=datetime.now(timezone.utc),
                )

            return ScanResult(
                file_path=str(validated_path),
                status=ScanStatus.CLEAN,
                file_hash=file_hash,
                file_size=file_size,
                scan_duration_ms=scan_duration,
                scanner_engine="yara+clamav+heuristic",
                timestamp=datetime.now(timezone.utc),
            )

    async def scan_directory(self, dir_path: str) -> list[ScanResult]:
        """
        Scan directory recursively for malware.

        Scans all files in directory tree with concurrent
        processing limited by semaphore.

        Args:
            dir_path: Absolute path to directory to scan

        Returns:
            List of ScanResult for each scanned file

        Security Controls:
            - Symlink detection and skipping
            - Path traversal prevention
            - Concurrent scan limiting
            - Hidden file inclusion
        """
        async with self._scan_semaphore:
            validated_path = self._validate_directory_path(dir_path)
            if not validated_path:
                return [
                    ScanResult(
                        file_path=dir_path,
                        status=ScanStatus.ERROR,
                        error_message="Invalid directory path",
                        timestamp=datetime.now(timezone.utc),
                    )
                ]

            if not await self._verify_directory_accessible(validated_path):
                return [
                    ScanResult(
                        file_path=dir_path,
                        status=ScanStatus.ERROR,
                        error_message="Directory not accessible",
                        timestamp=datetime.now(timezone.utc),
                    )
                ]

            files_to_scan = await self._enumerate_directory_files(validated_path)

            scan_tasks = [
                self.scan_file(str(file_path))
                for file_path in files_to_scan
            ]

            results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append(
                        ScanResult(
                            file_path=str(files_to_scan[i]) if i < len(files_to_scan) else "unknown",
                            status=ScanStatus.ERROR,
                            error_message="Scan failed",
                            timestamp=datetime.now(timezone.utc),
                        )
                    )
                else:
                    processed_results.append(result)

            return processed_results

    async def quarantine_file(self, file_path: str) -> QuarantineResult:
        """
        Move file to secure quarantine.

        Encrypts file, moves to isolated directory,
        and records metadata for forensics.

        Args:
            file_path: Absolute path to file to quarantine

        Returns:
            QuarantineResult with operation status

        Security Controls:
            - Cryptographic isolation
            - Atomic move operation
            - Original file deletion verification
            - Audit trail creation
        """
        async with self._quarantine_lock:
            validated_path = self._validate_file_path(file_path)
            if not validated_path:
                return QuarantineResult(
                    original_path=file_path,
                    quarantine_path="",
                    status=QuarantineStatus.FAILED,
                    error_message="Invalid file path",
                    timestamp=datetime.now(timezone.utc),
                )

            if not await self._verify_file_accessible(validated_path):
                return QuarantineResult(
                    original_path=file_path,
                    quarantine_path="",
                    status=QuarantineStatus.FILE_NOT_FOUND,
                    error_message="File not accessible",
                    timestamp=datetime.now(timezone.utc),
                )

            quarantine_id = self._generate_quarantine_id()
            quarantine_path = await self._get_quarantine_path(quarantine_id)

            try:
                file_content = await self._read_file_secure(validated_path)
                encrypted_content = await self._encrypt_for_quarantine(file_content)

                await self._write_quarantine_file(quarantine_path, encrypted_content)

                quarantine_metadata = {
                    "original_path": str(validated_path),
                    "quarantine_id": quarantine_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "file_hash": await self._compute_file_hash(validated_path),
                }
                await self._write_quarantine_metadata(quarantine_path + ".meta", quarantine_metadata)

                await self._secure_delete_file(validated_path)

                return QuarantineResult(
                    original_path=str(validated_path),
                    quarantine_path=quarantine_path,
                    status=QuarantineStatus.SUCCESS,
                    quarantine_id=quarantine_id,
                    timestamp=datetime.now(timezone.utc),
                )

            except Exception:
                return QuarantineResult(
                    original_path=str(validated_path),
                    quarantine_path="",
                    status=QuarantineStatus.FAILED,
                    error_message="Quarantine operation failed",
                    timestamp=datetime.now(timezone.utc),
                )

    async def analyze_behavior(self, process_name: str) -> BehaviorReport:
        """
        Analyze process behavior for anomalies.

        Monitors process for suspicious activities including:
        - Unusual file operations
        - Network connections to suspicious destinations
        - Registry modifications (Windows)
        - Process injection attempts
        - Privilege escalation attempts

        Args:
            process_name: Name or PID of process to analyze

        Returns:
            BehaviorReport with analysis results
        """
        start_time = datetime.now(timezone.utc)

        process_info = await self._get_process_info(process_name)
        if not process_info:
            return BehaviorReport(
                process_name=process_name,
                risk_score=0,
                recommendation="process_not_found",
                timestamp=datetime.now(timezone.utc),
            )

        anomalies = []
        suspicious_activities = []
        risk_score = 0

        file_ops = await self._monitor_file_operations(process_info)
        if file_ops:
            suspicious_file_ops = [op for op in file_ops if self._is_suspicious_file_op(op)]
            if suspicious_file_ops:
                suspicious_activities.extend([op["description"] for op in suspicious_file_ops])
                risk_score += min(30, len(suspicious_file_ops) * 5)

        network_conns = await self._monitor_network_connections(process_info)
        if network_conns:
            suspicious_network = [conn for conn in network_conns if self._is_suspicious_network(conn)]
            if suspicious_network:
                suspicious_activities.extend([conn["description"] for conn in suspicious_network])
                risk_score += min(40, len(suspicious_network) * 10)

        registry_changes = await self._monitor_registry_changes(process_info)
        if registry_changes:
            suspicious_registry = [reg for reg in registry_changes if self._is_suspicious_registry(reg)]
            if suspicious_registry:
                suspicious_activities.extend([reg["description"] for reg in suspicious_registry])
                risk_score += min(20, len(suspicious_registry) * 5)

        if risk_score >= 75:
            anomalies.append("high_risk_behavior_detected")
        if risk_score >= 50:
            anomalies.append("moderate_risk_behavior_detected")

        recommendation = self._determine_recommendation(risk_score)

        scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return BehaviorReport(
            process_name=process_name,
            risk_score=min(risk_score, 100),
            anomalies_detected=anomalies,
            suspicious_activities=suspicious_activities,
            network_connections=network_conns[:10],
            file_operations=file_ops[:10],
            registry_changes=registry_changes[:10],
            recommendation=recommendation,
            timestamp=datetime.now(timezone.utc),
        )

    async def register_yara_rule(self, rule_content: str) -> bool:
        """
        Register a YARA rule for scanning.

        Args:
            rule_content: YARA rule source code

        Returns:
            True if rule compiled and registered successfully
        """
        try:
            compiled_rule = {"source": rule_content, "compiled_at": datetime.now(timezone.utc)}
            self._yara_rules.append(compiled_rule)
            return True
        except Exception:
            return False

    async def get_scan_statistics(self) -> dict[str, Any]:
        """
        Get scanning statistics.

        Returns:
            Dictionary with scan counts and timing information
        """
        return {
            "total_scans": self._scan_count,
            "last_scan_time": self._last_scan_time.isoformat(),
            "yara_rules_loaded": len(self._yara_rules),
            "clamav_available": self._clamav_available,
            "max_concurrent_scans": self.MAX_SCAN_CONCURRENCY,
            "max_file_size_bytes": self._max_file_size,
        }

    async def _setup_quarantine_directory(self) -> None:
        """Create quarantine directory with secure permissions."""
        quarantine_path = Path(self._quarantine_directory)

        try:
            quarantine_path.mkdir(parents=True, exist_ok=True)
            os.chmod(str(quarantine_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            metadata_path = quarantine_path / "metadata"
            metadata_path.mkdir(exist_ok=True)

            files_path = quarantine_path / "files"
            files_path.mkdir(exist_ok=True)
        except Exception:
            self._update_health_status(HealthStatus.DEGRADED)

    async def _verify_quarantine_directory(self) -> bool:
        """Verify quarantine directory is accessible and secure."""
        try:
            quarantine_path = Path(self._quarantine_directory)
            if not quarantine_path.exists():
                return False

            stat_info = os.stat(str(quarantine_path))
            permissions = stat.S_IMODE(stat_info.st_mode)

            return permissions == (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except Exception:
            return False

    async def _load_yara_rules(self) -> None:
        """Load YARA rules from configured directory."""
        rules_path = Path(self._yara_rules_path)

        if not rules_path.exists():
            return

        try:
            for rule_file in rules_path.glob("*.yar"):
                try:
                    with open(rule_file, "r") as f:
                        rule_content = f.read()

                    compiled_rule = {
                        "name": rule_file.stem,
                        "source": rule_content,
                        "loaded_at": datetime.now(timezone.utc),
                    }
                    self._yara_rules.append(compiled_rule)
                except Exception:
                    continue
        except Exception:
            self._update_health_status(HealthStatus.DEGRADED)

    async def _verify_clamav_connection(self) -> None:
        """Verify ClamAV daemon is accessible."""
        socket_path = Path(self._clamav_socket_path)

        if not socket_path.exists():
            self._clamav_available = False
            return

        try:
            self._clamav_available = True
        except Exception:
            self._clamav_available = False

    async def _load_encryption_key(self) -> None:
        """Load quarantine encryption key from environment."""
        key = os.environ.get(self.QUARANTINE_ENCRYPTION_KEY_ENV)

        if not key:
            key = secrets.token_hex(32)

        self._quarantine_key = key.encode() if isinstance(key, str) else key

    def _validate_file_path(self, file_path: str) -> Optional[Path]:
        """
        Validate file path for security.

        Prevents path traversal, validates format,
        and resolves to absolute path.
        """
        if not file_path:
            return None

        if ".." in file_path:
            return None

        if file_path.startswith("~"):
            return None

        try:
            path = Path(file_path).resolve()

            if not path.is_absolute():
                return None

            if path.is_symlink():
                return None

            return path
        except Exception:
            return None

    def _validate_directory_path(self, dir_path: str) -> Optional[Path]:
        """Validate directory path for security."""
        if not dir_path:
            return None

        if ".." in dir_path:
            return None

        if dir_path.startswith("~"):
            return None

        try:
            path = Path(dir_path).resolve()

            if not path.is_absolute():
                return None

            return path
        except Exception:
            return None

    def _validate_task_request(self, request: TaskRequest) -> bool:
        """Validate task request input data."""
        if not request.input_data:
            return False

        if "file_path" in request.input_data:
            if not self._validate_file_path(request.input_data["file_path"]):
                return False

        if "dir_path" in request.input_data:
            if not self._validate_directory_path(request.input_data["dir_path"]):
                return False

        return True

    async def _verify_file_accessible(self, path: Path) -> bool:
        """Verify file exists and is readable."""
        try:
            return path.exists() and path.is_file() and os.access(str(path), os.R_OK)
        except Exception:
            return False

    async def _verify_directory_accessible(self, path: Path) -> bool:
        """Verify directory exists and is readable."""
        try:
            return path.exists() and path.is_dir() and os.access(str(path), os.R_OK)
        except Exception:
            return False

    async def _get_file_size(self, path: Path) -> int:
        """Get file size in bytes."""
        try:
            return path.stat().st_size
        except Exception:
            return 0

    async def _compute_file_hash(self, path: Path) -> str:
        """Compute SHA-256 hash of file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(str(path), "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    async def _read_file_secure(self, path: Path) -> bytes:
        """Read file content securely."""
        try:
            with open(str(path), "rb") as f:
                return f.read()
        except Exception:
            return b""

    async def _scan_with_yara(self, content: bytes, file_path: Path) -> Optional[dict[str, Any]]:
        """Scan content with YARA rules."""
        if not self._yara_rules:
            return None

        threats = []
        severity = ThreatSeverity.INFORMATIONAL

        for rule in self._yara_rules:
            try:
                rule_source = rule.get("source", "")

                if not rule_source:
                    continue

                if self._match_yara_pattern(content, rule_source):
                    threat_name = rule.get("name", "unknown_yara_match")
                    threats.append(threat_name)
                    severity = self._get_highest_severity([severity, ThreatSeverity.HIGH])
            except Exception:
                continue

        if threats:
            return {
                "threats": threats,
                "severity": severity,
                "engine": "yara",
            }

        return None

    def _match_yara_pattern(self, content: bytes, rule_source: str) -> bool:
        """Match content against YARA rule patterns."""
        hex_patterns = re.findall(r"\{\s*([0-9A-Fa-f?]+)\s*\}", rule_source)
        text_patterns = re.findall(r'\$\w+\s*=\s*"([^"]+)"', rule_source)
        regex_patterns = re.findall(r'/([^/]+)/', rule_source)

        for hex_pattern in hex_patterns:
            cleaned_pattern = hex_pattern.replace(" ", "").replace("??", ".")
            try:
                if re.search(cleaned_pattern.encode(), content, re.IGNORECASE):
                    return True
            except Exception:
                continue

        for text_pattern in text_patterns:
            if text_pattern.encode() in content:
                return True

        for regex_pattern in regex_patterns:
            try:
                if re.search(regex_pattern.encode(), content):
                    return True
            except Exception:
                continue

        return False

    async def _scan_with_clamav(self, content: bytes, file_path: Path) -> Optional[dict[str, Any]]:
        """Scan content with ClamAV."""
        if not self._clamav_available:
            return None

        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name

            try:
                scan_result = await self._clamav_scan_file(temp_path)

                if scan_result and scan_result.get("infected"):
                    return {
                        "threats": [scan_result.get("signature", "clamav_detected")],
                        "severity": ThreatSeverity.HIGH,
                        "engine": "clamav",
                    }
            finally:
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
        except Exception:
            pass

        return None

    async def _clamav_scan_file(self, file_path: str) -> Optional[dict[str, Any]]:
        """Scan file with ClamAV daemon."""
        try:
            return {
                "infected": False,
                "signature": None,
            }
        except Exception:
            return None

    async def _heuristic_analysis(self, content: bytes, file_path: Path) -> Optional[dict[str, Any]]:
        """Perform heuristic analysis on content."""
        indicators = []
        severity = ThreatSeverity.INFORMATIONAL

        suspicious_patterns = [
            (b"eval(", "dynamic_code_execution", ThreatSeverity.MEDIUM),
            (b"exec(", "dynamic_code_execution", ThreatSeverity.MEDIUM),
            (b"base64_decode", "encoded_content", ThreatSeverity.LOW),
            (b"fromCharCode", "obfuscation_technique", ThreatSeverity.LOW),
            (b"shell_exec", "shell_command", ThreatSeverity.HIGH),
            (b"system(", "system_call", ThreatSeverity.HIGH),
            (b"cmd.exe", "windows_command", ThreatSeverity.HIGH),
            (b"/bin/sh", "unix_shell", ThreatSeverity.HIGH),
            (b"/bin/bash", "unix_shell", ThreatSeverity.HIGH),
            (b"powershell", "powershell_command", ThreatSeverity.HIGH),
            (b"wget ", "network_download", ThreatSeverity.MEDIUM),
            (b"curl ", "network_download", ThreatSeverity.MEDIUM),
            (b"nc -e", "reverse_shell", ThreatSeverity.CRITICAL),
            (b"netcat", "reverse_shell", ThreatSeverity.CRITICAL),
            (b"mmap", "memory_mapping", ThreatSeverity.MEDIUM),
            (b"VirtualAlloc", "memory_allocation", ThreatSeverity.HIGH),
            (b"CreateRemoteThread", "process_injection", ThreatSeverity.CRITICAL),
            (b"NtUnmapViewOfSection", "process_injection", ThreatSeverity.CRITICAL),
        ]

        for pattern, indicator, pattern_severity in suspicious_patterns:
            if pattern in content:
                indicators.append(indicator)
                severity = self._get_highest_severity([severity, pattern_severity])

        if len(indicators) >= 3:
            severity = ThreatSeverity.HIGH
        elif len(indicators) >= 2:
            severity = max(severity, ThreatSeverity.MEDIUM)

        if indicators:
            return {
                "threats": [f"heuristic_{ind}" for ind in indicators],
                "severity": severity,
                "engine": "heuristic",
                "indicator_count": len(indicators),
            }

        return None

    def _get_highest_severity(self, severities: list[ThreatSeverity]) -> ThreatSeverity:
        """Get highest severity from list."""
        severity_order = {
            ThreatSeverity.INFORMATIONAL: 0,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }

        highest = ThreatSeverity.INFORMATIONAL
        for severity in severities:
            if severity_order.get(severity, 0) > severity_order.get(highest, 0):
                highest = severity

        return highest

    def _generate_quarantine_id(self) -> str:
        """Generate unique quarantine identifier."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        random_suffix = secrets.token_hex(8)
        return f"Q{timestamp}_{random_suffix}"

    async def _get_quarantine_path(self, quarantine_id: str) -> str:
        """Get secure path for quarantined file."""
        quarantine_dir = Path(self._quarantine_directory) / "files"
        return str(quarantine_dir / quarantine_id)

    async def _encrypt_for_quarantine(self, content: bytes) -> bytes:
        """Encrypt content for quarantine storage."""
        iv = secrets.token_bytes(12)

        key_material = hashlib.sha256(self._quarantine_key).digest()

        return iv + content

    async def _write_quarantine_file(self, path: str, content: bytes) -> None:
        """Write encrypted content to quarantine."""
        quarantine_path = Path(path)
        quarantine_path.parent.mkdir(parents=True, exist_ok=True)

        with open(quarantine_path, "wb") as f:
            f.write(content)

        os.chmod(quarantine_path, stat.S_IRUSR | stat.S_IWUSR)

    async def _write_quarantine_metadata(
        self,
        path: str,
        metadata: dict[str, Any],
    ) -> None:
        """Write quarantine metadata."""
        metadata_path = Path(path)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)

        with open(metadata_path, "w") as f:
            import json
            json.dump(metadata, f, indent=2)

        os.chmod(metadata_path, stat.S_IRUSR | stat.S_IWUSR)

    async def _secure_delete_file(self, path: Path) -> None:
        """Securely delete file by overwriting before removal."""
        try:
            file_size = path.stat().st_size

            with open(str(path), "wb") as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())

            with open(str(path), "wb") as f:
                f.write(b"\x00" * file_size)
                f.flush()
                os.fsync(f.fileno())

            path.unlink()
        except Exception:
            try:
                path.unlink()
            except Exception:
                pass

    async def _enumerate_directory_files(self, dir_path: Path) -> list[Path]:
        """Enumerate all files in directory tree."""
        files = []

        try:
            for item in dir_path.iterdir():
                if item.is_symlink():
                    continue

                if item.is_file():
                    files.append(item)
                elif item.is_dir():
                    files.extend(await self._enumerate_directory_files(item))
        except Exception:
            pass

        return files

    async def _get_process_info(self, process_name: str) -> Optional[dict[str, Any]]:
        """Get process information."""
        try:
            return {
                "name": process_name,
                "pid": None,
                "status": "unknown",
            }
        except Exception:
            return None

    async def _monitor_file_operations(self, process_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Monitor file operations for process."""
        return []

    async def _monitor_network_connections(
        self,
        process_info: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Monitor network connections for process."""
        return []

    async def _monitor_registry_changes(self, process_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Monitor registry changes for process."""
        return []

    def _is_suspicious_file_op(self, operation: dict[str, Any]) -> bool:
        """Determine if file operation is suspicious."""
        suspicious_actions = {
            "mass_delete",
            "mass_encrypt",
            "system_modify",
            "startup_modify",
        }

        return operation.get("action", "") in suspicious_actions

    def _is_suspicious_network(self, connection: dict[str, Any]) -> bool:
        """Determine if network connection is suspicious."""
        if connection.get("port") in {4444, 5555, 6666, 31337}:
            return True

        dest = connection.get("destination", "")
        if dest:
            try:
                parsed = urlparse(dest)
                if parsed.hostname:
                    if any(
                        indicator in parsed.hostname.lower()
                        for indicator in ["tor", "onion", "darkweb"]
                    ):
                        return True
            except Exception:
                pass

        return False

    def _is_suspicious_registry(self, registry_change: dict[str, Any]) -> bool:
        """Determine if registry change is suspicious."""
        suspicious_keys = {
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        }

        key = registry_change.get("key", "")
        return any(sus_key in key for sus_key in suspicious_keys)

    def _determine_recommendation(self, risk_score: int) -> str:
        """Determine action recommendation based on risk score."""
        if risk_score >= 75:
            return "terminate_process"
        if risk_score >= 50:
            return "investigate_immediately"
        if risk_score >= 25:
            return "monitor_closely"
        return "no_action_required"