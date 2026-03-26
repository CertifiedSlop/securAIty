"""
Security Engineer Agent

Cryptography management, authentication system review, security hardening,
TLS/certificate validation, and security configuration auditing.
"""

import asyncio
import ssl
import socket
import hashlib
import hmac
import secrets
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Optional
from pathlib import Path

from ..base import BaseAgent, HealthStatus, TaskRequest, TaskResult, TaskPriority, AgentCapability


class CryptoAlgorithmCategory(str, Enum):
    """Cryptographic algorithm categories."""

    ENCRYPTION = "encryption"
    HASHING = "hashing"
    KEY_DERIVATION = "key_derivation"
    SIGNATURE = "signature"
    KEY_EXCHANGE = "key_exchange"
    RANDOM_GENERATION = "random_generation"


class SeverityLevel(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStandard(str, Enum):
    """Security compliance standards."""

    OWASP_TOP10 = "OWASP_Top10"
    NIST_800_53 = "NIST_800_53"
    NIST_800_171 = "NIST_800_171"
    PCI_DSS = "PCI_DSS"
    FIPS_140_2 = "FIPS_140_2"
    CIS = "CIS"


@dataclass
class CryptoFinding:
    """
    Cryptographic security finding.

    Attributes:
        finding_id: Unique identifier
        severity: Severity level
        category: Algorithm category
        description: Finding description
        recommendation: Remediation recommendation
        affected_component: Affected component name
        compliance_violations: List of violated compliance standards
    """

    finding_id: str
    severity: SeverityLevel
    category: CryptoAlgorithmCategory
    description: str
    recommendation: str
    affected_component: str
    compliance_violations: list[str] = field(default_factory=list)


@dataclass
class CryptoAuditResult:
    """
    Result of cryptographic configuration audit.

    Attributes:
        audit_id: Unique audit identifier
        timestamp: When audit was performed
        passed: Whether configuration passed all checks
        score: Security score (0-100)
        findings: List of security findings
        compliant_algorithms: List of approved algorithms found
        deprecated_algorithms: List of deprecated algorithms detected
        key_strength_assessment: Assessment of key lengths
        random_quality: Quality of random number generation
        recommendations: List of recommendations
    """

    audit_id: str
    timestamp: datetime
    passed: bool
    score: float
    findings: list[CryptoFinding] = field(default_factory=list)
    compliant_algorithms: list[str] = field(default_factory=list)
    deprecated_algorithms: list[str] = field(default_factory=list)
    key_strength_assessment: dict[str, Any] = field(default_factory=dict)
    random_quality: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class AuthFinding:
    """
    Authentication security finding.

    Attributes:
        finding_id: Unique identifier
        severity: Severity level
        category: Finding category
        description: Finding description
        recommendation: Remediation recommendation
        affected_component: Affected component
        cvss_score: Optional CVSS score
    """

    finding_id: str
    severity: SeverityLevel
    category: str
    description: str
    recommendation: str
    affected_component: str
    cvss_score: Optional[float] = None


@dataclass
class AuthReviewResult:
    """
    Result of authentication system review.

    Attributes:
        review_id: Unique review identifier
        timestamp: When review was performed
        passed: Whether system passed all checks
        score: Security score (0-100)
        findings: List of security findings
        password_policy_assessment: Password policy evaluation
        session_management_assessment: Session management evaluation
        mfa_status: MFA implementation status
        token_security: Token handling assessment
        compliance_mapping: Mapping to compliance standards
    """

    review_id: str
    timestamp: datetime
    passed: bool
    score: float
    findings: list[AuthFinding] = field(default_factory=list)
    password_policy_assessment: dict[str, Any] = field(default_factory=dict)
    session_management_assessment: dict[str, Any] = field(default_factory=dict)
    mfa_status: dict[str, Any] = field(default_factory=dict)
    token_security: dict[str, Any] = field(default_factory=dict)
    compliance_mapping: dict[str, Any] = field(default_factory=dict)


@dataclass
class HardeningFinding:
    """
    Security hardening finding.

    Attributes:
        finding_id: Unique identifier
        severity: Severity level
        category: Finding category
        description: Finding description
        current_state: Current configuration state
        recommended_state: Recommended configuration state
        remediation_steps: Steps to remediate
        references: List of reference URLs/documents
    """

    finding_id: str
    severity: SeverityLevel
    category: str
    description: str
    current_state: str
    recommended_state: str
    remediation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class HardeningReport:
    """
    Security hardening recommendations report.

    Attributes:
        report_id: Unique report identifier
        timestamp: When report was generated
        system_type: Type of system analyzed
        overall_score: Overall hardening score (0-100)
        findings: List of findings
        recommendations: Prioritized recommendations
        compliance_score: Compliance framework score
        risk_level: Overall risk level
        executive_summary: High-level summary
    """

    report_id: str
    timestamp: datetime
    system_type: str
    overall_score: float
    findings: list[HardeningFinding] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    compliance_score: dict[str, float] = field(default_factory=dict)
    risk_level: SeverityLevel = SeverityLevel.INFO
    executive_summary: str = ""


@dataclass
class CertificateInfo:
    """
    Certificate information.

    Attributes:
        subject: Certificate subject
        issuer: Certificate issuer
        valid_from: Validity start date
        valid_to: Validity end date
        serial_number: Certificate serial number
        signature_algorithm: Signature algorithm used
        key_size: Public key size in bits
        san: Subject Alternative Names
        is_self_signed: Whether certificate is self-signed
        days_until_expiry: Days until expiration
    """

    subject: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    serial_number: str
    signature_algorithm: str
    key_size: int
    san: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    days_until_expiry: int = 0


@dataclass
class TLSValidationResult:
    """
    Result of TLS configuration validation.

    Attributes:
        validation_id: Unique validation identifier
        timestamp: When validation was performed
        hostname: Validated hostname
        passed: Whether validation passed
        score: Security score (0-100)
        tls_version: Negotiated TLS version
        cipher_suite: Negotiated cipher suite
        certificate: Certificate information
        chain_valid: Whether certificate chain is valid
        protocol_vulnerabilities: Detected protocol vulnerabilities
        supported_versions: List of supported TLS versions
        supported_ciphers: List of supported cipher suites
        security_headers: Security header assessment
        recommendations: List of recommendations
    """

    validation_id: str
    timestamp: datetime
    hostname: str
    passed: bool
    score: float
    tls_version: str = ""
    cipher_suite: str = ""
    certificate: Optional[CertificateInfo] = None
    chain_valid: bool = False
    protocol_vulnerabilities: list[str] = field(default_factory=list)
    supported_versions: list[str] = field(default_factory=list)
    supported_ciphers: list[str] = field(default_factory=list)
    security_headers: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


class SecurityEngineerAgent(BaseAgent):
    """
    Security Engineer agent for cryptographic and authentication security.

    Provides comprehensive security analysis including:
    - Cryptography configuration validation
    - Authentication system review
    - Security hardening recommendations
    - TLS/certificate validation
    - Security configuration auditing

    Follows OWASP, NIST, and industry best practices.
    """

    DEPRECATED_ALGORITHMS: frozenset = frozenset({
        "MD5",
        "SHA1",
        "DES",
        "3DES",
        "RC4",
        "RC2",
        "BLOWFISH",
        "ECB",
        "PKCS1V1.5",
        "TLS1.0",
        "TLS1.1",
        "SSL2.0",
        "SSL3.0",
    })

    APPROVED_ENCRYPTION: frozenset = frozenset({
        "AES-256-GCM",
        "AES-128-GCM",
        "AES-256-GCM-SIV",
        "CHACHA20-POLY1305",
        "XCHACHA20-POLY1305",
    })

    APPROVED_HASHING: frozenset = frozenset({
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "BLAKE2B",
        "BLAKE2S",
        "BLAKE3",
    })

    APPROVED_PASSWORD_HASHING: frozenset = frozenset({
        "ARGON2ID",
        "ARGON2I",
        "ARGON2D",
        "SCRYPT",
        "PBKDF2-HMAC-SHA256",
        "PBKDF2-HMAC-SHA512",
        "BCRYPT",
        "YESCRYPT",
    })

    APPROVED_SIGNATURE: frozenset = frozenset({
        "ED25519",
        "ED448",
        "ECDSA-P256",
        "ECDSA-P384",
        "ECDSA-P521",
        "RSA-PSS",
        "RSA-OAEP",
    })

    APPROVED_KEY_EXCHANGE: frozenset = frozenset({
        "X25519",
        "X448",
        "ECDH-P256",
        "ECDH-P384",
        "ECDH-P521",
        "KYBER768",
    })

    MIN_KEY_LENGTHS: dict[str, int] = field(default_factory=lambda: {
        "AES": 128,
        "RSA": 2048,
        "ECDSA": 256,
        "ED25519": 256,
        "DH": 2048,
        "ECDH": 256,
    })

    def __init__(
        self,
        agent_id: str = "security_engineer_agent",
        version: str = "1.0.0",
    ) -> None:
        """
        Initialize security engineer agent.

        Args:
            agent_id: Unique agent identifier
            version: Agent version string
        """
        super().__init__(agent_type="security_engineer", version=version)

        self._audit_history: list[CryptoAuditResult] = []
        self._review_history: list[AuthReviewResult] = []
        self._validation_history: list[TLSValidationResult] = []

        self._register_capabilities()

    def _register_capabilities(self) -> None:
        """Register agent capabilities."""
        self._register_capability(
            AgentCapability(
                name="validate_crypto_config",
                description="Validate cryptographic configuration against best practices",
                input_schema={
                    "type": "object",
                    "properties": {
                        "config": {
                            "type": "object",
                            "description": "Cryptographic configuration to validate",
                        },
                    },
                    "required": ["config"],
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "audit_id": {"type": "string"},
                        "passed": {"type": "boolean"},
                        "score": {"type": "number"},
                        "findings": {"type": "array"},
                    },
                },
                timeout=30.0,
            )
        )

        self._register_capability(
            AgentCapability(
                name="review_auth_system",
                description="Review authentication system security",
                input_schema={
                    "type": "object",
                    "properties": {
                        "auth_config": {
                            "type": "object",
                            "description": "Authentication configuration",
                        },
                    },
                    "required": ["auth_config"],
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "review_id": {"type": "string"},
                        "passed": {"type": "boolean"},
                        "score": {"type": "number"},
                        "findings": {"type": "array"},
                    },
                },
                timeout=30.0,
            )
        )

        self._register_capability(
            AgentCapability(
                name="generate_hardening_recommendations",
                description="Generate security hardening recommendations",
                input_schema={
                    "type": "object",
                    "properties": {
                        "system_type": {
                            "type": "string",
                            "description": "Type of system to harden",
                        },
                    },
                    "required": ["system_type"],
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "report_id": {"type": "string"},
                        "overall_score": {"type": "number"},
                        "recommendations": {"type": "array"},
                    },
                },
                timeout=30.0,
            )
        )

        self._register_capability(
            AgentCapability(
                name="validate_tls_config",
                description="Validate TLS configuration and certificates",
                input_schema={
                    "type": "object",
                    "properties": {
                        "hostname": {
                            "type": "string",
                            "description": "Hostname to validate",
                        },
                        "port": {
                            "type": "integer",
                            "description": "Port number (default: 443)",
                        },
                    },
                    "required": ["hostname"],
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "validation_id": {"type": "string"},
                        "passed": {"type": "boolean"},
                        "score": {"type": "number"},
                        "tls_version": {"type": "string"},
                    },
                },
                timeout=30.0,
            )
        )

    async def initialize(self) -> None:
        """Initialize the security engineer agent."""
        self._initialized = True
        self._update_health_status(HealthStatus.HEALTHY)

    async def execute(self, request: TaskRequest) -> TaskResult:
        """
        Execute a security engineering task.

        Args:
            request: Task request with capability and input data

        Returns:
            TaskResult with execution results
        """
        start_time = datetime.now(timezone.utc)

        try:
            if request.capability == "validate_crypto_config":
                result = await self.validate_crypto_config(
                    request.input_data.get("config", {})
                )
                output = self._crypto_result_to_dict(result)

            elif request.capability == "review_auth_system":
                result = await self.review_auth_system(
                    request.input_data.get("auth_config", {})
                )
                output = self._auth_result_to_dict(result)

            elif request.capability == "generate_hardening_recommendations":
                result = await self.generate_hardening_recommendations(
                    request.input_data.get("system_type", "generic")
                )
                output = self._hardening_report_to_dict(result)

            elif request.capability == "validate_tls_config":
                result = await self.validate_tls_config(
                    request.input_data.get("hostname", ""),
                    request.input_data.get("port", 443),
                )
                output = self._tls_result_to_dict(result)

            else:
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message=f"Unknown capability: {request.capability}",
                )

            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            return TaskResult.success(
                task_id=request.task_id,
                output_data=output,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return TaskResult.failure(
                task_id=request.task_id,
                error_message=str(e),
                execution_time_ms=execution_time,
            )

    async def health_check(self) -> HealthStatus:
        """Perform health check on the agent."""
        if not self._initialized:
            return HealthStatus.UNHEALTHY
        return HealthStatus.HEALTHY

    async def shutdown(self) -> None:
        """Gracefully shutdown the agent."""
        self._initialized = False
        self._update_health_status(HealthStatus.UNKNOWN)

    async def validate_crypto_config(self, config: dict[str, Any]) -> CryptoAuditResult:
        """
        Validate cryptographic configuration against best practices.

        Checks for:
        - Approved algorithms and key lengths
        - Deprecated/weak algorithms
        - Secure random number generation
        - Proper key management
        - Compliance with OWASP, NIST standards

        Args:
            config: Cryptographic configuration dictionary

        Returns:
            CryptoAuditResult with validation findings
        """
        audit_id = f"crypto_audit_{secrets.token_hex(8)}"
        timestamp = datetime.now(timezone.utc)
        findings: list[CryptoFinding] = []
        compliant: list[str] = []
        deprecated: list[str] = []

        await self._check_encryption_config(config, findings, compliant, deprecated)
        await self._check_hashing_config(config, findings, compliant, deprecated)
        await self._check_password_hashing_config(config, findings, compliant, deprecated)
        await self._check_signature_config(config, findings, compliant, deprecated)
        await self._check_key_exchange_config(config, findings, compliant, deprecated)
        await self._check_random_generation_config(config, findings, compliant, deprecated)
        await self._check_key_management_config(config, findings, compliant, deprecated)

        score = self._calculate_crypto_score(findings, compliant, deprecated)
        passed = score >= 80 and not any(f.severity == SeverityLevel.CRITICAL for f in findings)

        recommendations = self._generate_crypto_recommendations(findings)

        result = CryptoAuditResult(
            audit_id=audit_id,
            timestamp=timestamp,
            passed=passed,
            score=score,
            findings=findings,
            compliant_algorithms=compliant,
            deprecated_algorithms=deprecated,
            key_strength_assessment=self._assess_key_strengths(config),
            random_quality=self._assess_random_quality(config),
            recommendations=recommendations,
        )

        self._audit_history.append(result)
        return result

    async def review_auth_system(self, auth_config: dict[str, Any]) -> AuthReviewResult:
        """
        Review authentication system security.

        Evaluates:
        - Password policy strength
        - Session management security
        - MFA implementation
        - Token handling
        - Authentication flow security

        Args:
            auth_config: Authentication configuration dictionary

        Returns:
            AuthReviewResult with security assessment
        """
        review_id = f"auth_review_{secrets.token_hex(8)}"
        timestamp = datetime.now(timezone.utc)
        findings: list[AuthFinding] = []

        password_assessment = await self._review_password_policy(auth_config, findings)
        session_assessment = await self._review_session_management(auth_config, findings)
        mfa_status = await self._review_mfa_config(auth_config, findings)
        token_security = await self._review_token_handling(auth_config, findings)

        score = self._calculate_auth_score(findings)
        passed = score >= 75 and not any(f.severity == SeverityLevel.CRITICAL for f in findings)

        compliance_mapping = self._map_auth_compliance(findings)

        result = AuthReviewResult(
            review_id=review_id,
            timestamp=timestamp,
            passed=passed,
            score=score,
            findings=findings,
            password_policy_assessment=password_assessment,
            session_management_assessment=session_assessment,
            mfa_status=mfa_status,
            token_security=token_security,
            compliance_mapping=compliance_mapping,
        )

        self._review_history.append(result)
        return result

    async def generate_hardening_recommendations(
        self,
        system_type: str,
    ) -> HardeningReport:
        """
        Generate security hardening recommendations.

        Supports system types:
        - web_server
        - database
        - container
        - kubernetes
        - cloud
        - network
        - generic

        Args:
            system_type: Type of system to harden

        Returns:
            HardeningReport with recommendations
        """
        report_id = f"hardening_{secrets.token_hex(8)}"
        timestamp = datetime.now(timezone.utc)
        findings: list[HardeningFinding] = []

        await self._generate_os_hardening(system_type, findings)
        await self._generate_network_hardening(system_type, findings)
        await self._generate_application_hardening(system_type, findings)
        await self._generate_access_hardening(system_type, findings)
        await self._generate_logging_hardening(system_type, findings)

        overall_score = self._calculate_hardening_score(findings)
        recommendations = self._prioritize_recommendations(findings)
        compliance_scores = self._calculate_compliance_scores(findings)
        risk_level = self._determine_risk_level(findings, overall_score)
        executive_summary = self._generate_executive_summary(
            system_type, overall_score, risk_level, len(findings)
        )

        return HardeningReport(
            report_id=report_id,
            timestamp=timestamp,
            system_type=system_type,
            overall_score=overall_score,
            findings=findings,
            recommendations=recommendations,
            compliance_score=compliance_scores,
            risk_level=risk_level,
            executive_summary=executive_summary,
        )

    async def validate_tls_config(
        self,
        hostname: str,
        port: int = 443,
    ) -> TLSValidationResult:
        """
        Validate TLS configuration and certificates.

        Checks:
        - TLS version (requires 1.2+, prefers 1.3)
        - Cipher suite strength
        - Certificate validity and chain
        - Protocol vulnerabilities
        - Security headers

        Args:
            hostname: Hostname to validate
            port: Port number (default: 443)

        Returns:
            TLSValidationResult with validation details
        """
        validation_id = f"tls_validation_{secrets.token_hex(8)}"
        timestamp = datetime.now(timezone.utc)
        recommendations: list[str] = []
        protocol_vulns: list[str] = []
        supported_versions: list[str] = []
        supported_ciphers: list[str] = []

        tls_version = ""
        cipher_suite = ""
        cert_info: Optional[CertificateInfo] = None
        chain_valid = False
        score = 100.0

        try:
            tls_version, cipher_suite, cert_info, chain_valid = await self._probe_tls(
                hostname, port
            )

            if tls_version:
                supported_versions.append(tls_version)
                version_score = self._evaluate_tls_version(tls_version)
                score = min(score, version_score)

                if version_score < 80:
                    recommendations.append(f"Upgrade from TLS {tls_version} to TLS 1.3")

            if cipher_suite:
                supported_ciphers.append(cipher_suite)
                cipher_score = self._evaluate_cipher_suite(cipher_suite)
                score = min(score, cipher_score)

                if cipher_score < 80:
                    recommendations.append(f"Replace weak cipher suite: {cipher_suite}")

            if cert_info:
                cert_score = self._evaluate_certificate(cert_info)
                score = min(score, cert_score)

                if cert_info.days_until_expiry < 30:
                    recommendations.append(
                        f"Certificate expires in {cert_info.days_until_expiry} days - renew immediately"
                    )
                elif cert_info.days_until_expiry < 90:
                    recommendations.append(
                        f"Certificate expires in {cert_info.days_until_expiry} days - plan renewal"
                    )

                if cert_info.is_self_signed:
                    recommendations.append("Replace self-signed certificate with CA-signed certificate")
                    score = min(score, 60)

                if cert_info.key_size < 2048:
                    recommendations.append(f"Increase key size from {cert_info.key_size} to at least 2048 bits")

            await self._check_protocol_vulnerabilities(hostname, port, protocol_vulns)

        except Exception as e:
            recommendations.append(f"TLS probe failed: {str(e)}")
            score = 0.0

        passed = score >= 70 and not protocol_vulns

        security_headers = await self._check_security_headers(hostname, port)
        if not security_headers.get("strict_transport_security"):
            recommendations.append("Add HSTS (HTTP Strict Transport Security) header")

        return TLSValidationResult(
            validation_id=validation_id,
            timestamp=timestamp,
            hostname=hostname,
            passed=passed,
            score=max(0, score),
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            certificate=cert_info,
            chain_valid=chain_valid,
            protocol_vulnerabilities=protocol_vulns,
            supported_versions=supported_versions,
            supported_ciphers=supported_ciphers,
            security_headers=security_headers,
            recommendations=recommendations,
        )

    async def _check_encryption_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check encryption algorithm configuration."""
        encryption = config.get("encryption", {})
        algorithms = encryption.get("algorithms", [])

        for algo in algorithms:
            algo_upper = algo.upper()
            if any(d in algo_upper for d in self.DEPRECATED_ALGORITHMS):
                deprecated.append(algo)
                findings.append(CryptoFinding(
                    finding_id=f"enc_deprecated_{secrets.token_hex(4)}",
                    severity=SeverityLevel.CRITICAL,
                    category=CryptoAlgorithmCategory.ENCRYPTION,
                    description=f"Deprecated encryption algorithm: {algo}",
                    recommendation=f"Replace {algo} with AES-256-GCM or ChaCha20-Poly1305",
                    affected_component=encryption.get("component", "unknown"),
                    compliance_violations=["OWASP_A04", "NIST_SC-12", "PCI_DSS_3.4.1"],
                ))
            elif any(a in algo_upper for a in self.APPROVED_ENCRYPTION):
                compliant.append(algo)
            else:
                findings.append(CryptoFinding(
                    finding_id=f"enc_unknown_{secrets.token_hex(4)}",
                    severity=SeverityLevel.MEDIUM,
                    category=CryptoAlgorithmCategory.ENCRYPTION,
                    description=f"Unknown encryption algorithm: {algo}",
                    recommendation="Verify algorithm security or use approved algorithms",
                    affected_component=encryption.get("component", "unknown"),
                    compliance_violations=["OWASP_A04"],
                ))

        key_length = encryption.get("key_length", 0)
        if key_length > 0 and key_length < 128:
            findings.append(CryptoFinding(
                finding_id=f"enc_weak_key_{secrets.token_hex(4)}",
                severity=SeverityLevel.HIGH,
                category=CryptoAlgorithmCategory.ENCRYPTION,
                description=f"Weak key length: {key_length} bits",
                recommendation="Use minimum 128-bit keys, prefer 256-bit",
                affected_component=encryption.get("component", "unknown"),
                compliance_violations=["NIST_SC-12", "FIPS_140_2"],
            ))

    async def _check_hashing_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check hashing algorithm configuration."""
        hashing = config.get("hashing", {})
        algorithms = hashing.get("algorithms", [])

        for algo in algorithms:
            algo_upper = algo.upper()
            if "MD5" in algo_upper or "SHA1" in algo_upper or "SHA-1" in algo_upper:
                deprecated.append(algo)
                findings.append(CryptoFinding(
                    finding_id=f"hash_deprecated_{secrets.token_hex(4)}",
                    severity=SeverityLevel.CRITICAL,
                    category=CryptoAlgorithmCategory.HASHING,
                    description=f"Deprecated hash algorithm: {algo}",
                    recommendation=f"Replace {algo} with SHA-256 or SHA-3",
                    affected_component=hashing.get("component", "unknown"),
                    compliance_violations=["OWASP_A04", "NIST_SA-10", "PCI_DSS_3.4.2"],
                ))
            elif any(a in algo_upper for a in self.APPROVED_HASHING):
                compliant.append(algo)

    async def _check_password_hashing_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check password hashing configuration."""
        password_hashing = config.get("password_hashing", {})
        algorithm = password_hashing.get("algorithm", "")

        if algorithm:
            algo_upper = algorithm.upper()
            if "MD5" in algo_upper or "SHA1" in algo_upper or "SHA-1" in algo_upper or "PLAIN" in algo_upper:
                deprecated.append(algorithm)
                findings.append(CryptoFinding(
                    finding_id=f"pwd_hash_deprecated_{secrets.token_hex(4)}",
                    severity=SeverityLevel.CRITICAL,
                    category=CryptoAlgorithmCategory.KEY_DERIVATION,
                    description=f"Insecure password hashing: {algorithm}",
                    recommendation="Use Argon2id, scrypt, or PBKDF2-HMAC-SHA256",
                    affected_component=password_hashing.get("component", "unknown"),
                    compliance_violations=["OWASP_A04", "NIST_IA-5", "PCI_DSS_8.2.1"],
                ))
            elif any(a in algo_upper for a in self.APPROVED_PASSWORD_HASHING):
                compliant.append(algorithm)

                iterations = password_hashing.get("iterations", 0)
                memory_cost = password_hashing.get("memory_cost", 0)

                if "PBKDF2" in algo_upper and iterations < 100000:
                    findings.append(CryptoFinding(
                        finding_id=f"pwd_hash_weak_{secrets.token_hex(4)}",
                        severity=SeverityLevel.MEDIUM,
                        category=CryptoAlgorithmCategory.KEY_DERIVATION,
                        description=f"Low PBKDF2 iterations: {iterations}",
                        recommendation="Use minimum 100,000 iterations for PBKDF2",
                        affected_component=password_hashing.get("component", "unknown"),
                        compliance_violations=["NIST_IA-5"],
                    ))

                if "ARGON2" in algo_upper and memory_cost < 65536:
                    findings.append(CryptoFinding(
                        finding_id=f"pwd_hash_memory_{secrets.token_hex(4)}",
                        severity=SeverityLevel.LOW,
                        category=CryptoAlgorithmCategory.KEY_DERIVATION,
                        description=f"Low Argon2 memory cost: {memory_cost}",
                        recommendation="Use minimum 64MB (65536 KB) memory cost for Argon2",
                        affected_component=password_hashing.get("component", "unknown"),
                        compliance_violations=[],
                    ))

    async def _check_signature_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check signature algorithm configuration."""
        signature = config.get("signature", {})
        algorithms = signature.get("algorithms", [])

        for algo in algorithms:
            algo_upper = algo.upper()
            if "PKCS1V1.5" in algo_upper or ("RSA" in algo_upper and "PSS" not in algo_upper and "OAEP" not in algo_upper):
                deprecated.append(algo)
                findings.append(CryptoFinding(
                    finding_id=f"sig_deprecated_{secrets.token_hex(4)}",
                    severity=SeverityLevel.HIGH,
                    category=CryptoAlgorithmCategory.SIGNATURE,
                    description=f"Weak signature padding: {algo}",
                    recommendation="Use RSA-PSS or EdDSA (Ed25519)",
                    affected_component=signature.get("component", "unknown"),
                    compliance_violations=["NIST_SA-10"],
                ))
            elif any(a in algo_upper for a in self.APPROVED_SIGNATURE):
                compliant.append(algo)

    async def _check_key_exchange_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check key exchange configuration."""
        key_exchange = config.get("key_exchange", {})
        algorithms = key_exchange.get("algorithms", [])

        for algo in algorithms:
            algo_upper = algo.upper()
            if "DH" in algo_upper and "ECDH" not in algo_upper:
                key_size = key_exchange.get("key_size", 0)
                if key_size > 0 and key_size < 2048:
                    deprecated.append(algo)
                    findings.append(CryptoFinding(
                        finding_id=f"kx_weak_dh_{secrets.token_hex(4)}",
                        severity=SeverityLevel.HIGH,
                        category=CryptoAlgorithmCategory.KEY_EXCHANGE,
                        description=f"Weak DH key exchange: {key_size} bits",
                        recommendation="Use minimum 2048-bit DH or prefer ECDH/X25519",
                        affected_component=key_exchange.get("component", "unknown"),
                        compliance_violations=["NIST_SC-12"],
                    ))
            elif any(a in algo_upper for a in self.APPROVED_KEY_EXCHANGE):
                compliant.append(algo)

    async def _check_random_generation_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check random number generation configuration."""
        random_config = config.get("random_generation", {})
        source = random_config.get("source", "")

        if source:
            source_upper = source.upper()
            if "MATH" in source_upper or "RANDOM" in source_upper and "CRYPTO" not in source_upper:
                deprecated.append(source)
                findings.append(CryptoFinding(
                    finding_id=f"rng_insecure_{secrets.token_hex(4)}",
                    severity=SeverityLevel.CRITICAL,
                    category=CryptoAlgorithmCategory.RANDOM_GENERATION,
                    description=f"Insecure random source: {source}",
                    recommendation="Use cryptographically secure PRNG (CSPRNG)",
                    affected_component=random_config.get("component", "unknown"),
                    compliance_violations=["OWASP_A04", "CWE-331", "NIST_SC-12"],
                ))
            elif "CSPRNG" in source_upper or "SECURE" in source_upper or "URANDOM" in source_upper:
                compliant.append(source)

    async def _check_key_management_config(
        self,
        config: dict[str, Any],
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> None:
        """Check key management configuration."""
        key_mgmt = config.get("key_management", {})

        storage = key_mgmt.get("storage", "")
        if storage:
            storage_upper = storage.upper()
            if "PLAINTEXT" in storage_upper or "HARDCODED" in storage_upper:
                findings.append(CryptoFinding(
                    finding_id=f"key_storage_insecure_{secrets.token_hex(4)}",
                    severity=SeverityLevel.CRITICAL,
                    category=CryptoAlgorithmCategory.KEY_DERIVATION,
                    description=f"Insecure key storage: {storage}",
                    recommendation="Use HSM, KMS, or secure vault for key storage",
                    affected_component=key_mgmt.get("component", "unknown"),
                    compliance_violations=["OWASP_A04", "NIST_SC-12", "PCI_DSS_3.5"],
                ))
            elif "HSM" in storage_upper or "KMS" in storage_upper or "VAULT" in storage_upper:
                compliant.append(f"key_storage_{storage}")

        rotation_days = key_mgmt.get("rotation_days", 0)
        if rotation_days == 0:
            findings.append(CryptoFinding(
                finding_id=f"key_no_rotation_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category=CryptoAlgorithmCategory.KEY_DERIVATION,
                description="No key rotation policy configured",
                recommendation="Implement key rotation (90 days or less for sensitive keys)",
                affected_component=key_mgmt.get("component", "unknown"),
                compliance_violations=["NIST_SC-12", "PCI_DSS_3.6"],
            ))
        elif rotation_days > 90:
            findings.append(CryptoFinding(
                finding_id=f"key_rotation_slow_{secrets.token_hex(4)}",
                severity=SeverityLevel.LOW,
                category=CryptoAlgorithmCategory.KEY_DERIVATION,
                description=f"Key rotation period too long: {rotation_days} days",
                recommendation="Rotate keys every 90 days or less",
                affected_component=key_mgmt.get("component", "unknown"),
                compliance_violations=[],
            ))

    def _calculate_crypto_score(
        self,
        findings: list[CryptoFinding],
        compliant: list[str],
        deprecated: list[str],
    ) -> float:
        """Calculate cryptographic configuration score."""
        score = 100.0

        severity_penalties = {
            SeverityLevel.CRITICAL: 25.0,
            SeverityLevel.HIGH: 15.0,
            SeverityLevel.MEDIUM: 8.0,
            SeverityLevel.LOW: 3.0,
            SeverityLevel.INFO: 1.0,
        }

        for finding in findings:
            score -= severity_penalties.get(finding.severity, 0)

        if deprecated:
            score -= min(20.0, len(deprecated) * 5.0)

        compliant_bonus = min(20.0, len(compliant) * 2.0)
        score += compliant_bonus

        return max(0.0, min(100.0, score))

    def _assess_key_strengths(self, config: dict[str, Any]) -> dict[str, Any]:
        """Assess key strengths in configuration."""
        assessment = {
            "adequate": [],
            "weak": [],
            "unknown": [],
        }

        key_mgmt = config.get("key_management", {})
        keys = key_mgmt.get("keys", [])

        for key in keys:
            key_type = key.get("type", "unknown")
            key_size = key.get("size", 0)
            min_required = self.MIN_KEY_LENGTHS.get(key_type.upper(), 128)

            if key_size >= min_required:
                assessment["adequate"].append(f"{key_type}:{key_size}")
            elif key_size > 0:
                assessment["weak"].append(f"{key_type}:{key_size}")
            else:
                assessment["unknown"].append(key_type)

        return assessment

    def _assess_random_quality(self, config: dict[str, Any]) -> dict[str, Any]:
        """Assess random number generation quality."""
        random_config = config.get("random_generation", {})
        source = random_config.get("source", "unknown")

        return {
            "source": source,
            "is_csprng": "CSPRNG" in source.upper() or "SECURE" in source.upper() or "URANDOM" in source.upper(),
            "suitable_for_crypto": "CSPRNG" in source.upper() or "SECURE" in source.upper() or "URANDOM" in source.upper(),
        }

    def _generate_crypto_recommendations(self, findings: list[CryptoFinding]) -> list[str]:
        """Generate recommendations from findings."""
        recommendations = []
        seen = set()

        for finding in findings:
            if finding.recommendation not in seen:
                recommendations.append(finding.recommendation)
                seen.add(finding.recommendation)

        return sorted(recommendations, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
            next((f.severity.value for f in findings if f.recommendation == x), "INFO")
        ))

    async def _review_password_policy(
        self,
        auth_config: dict[str, Any],
        findings: list[AuthFinding],
    ) -> dict[str, Any]:
        """Review password policy configuration."""
        policy = auth_config.get("password_policy", {})

        assessment = {
            "min_length": policy.get("min_length", 0),
            "require_uppercase": policy.get("require_uppercase", False),
            "require_lowercase": policy.get("require_lowercase", False),
            "require_numbers": policy.get("require_numbers", False),
            "require_special": policy.get("require_special", False),
            "max_age_days": policy.get("max_age_days", 0),
            "history_count": policy.get("history_count", 0),
            "lockout_threshold": policy.get("lockout_threshold", 0),
        }

        min_length = policy.get("min_length", 0)
        if min_length < 8:
            findings.append(AuthFinding(
                finding_id=f"pwd_policy_length_{secrets.token_hex(4)}",
                severity=SeverityLevel.HIGH,
                category="password_policy",
                description=f"Minimum password length too short: {min_length}",
                recommendation="Require minimum 12 characters (8 absolute minimum)",
                affected_component="password_policy",
                cvss_score=6.5,
            ))

        if not policy.get("require_special", False):
            findings.append(AuthFinding(
                finding_id=f"pwd_policy_complex_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="password_policy",
                description="Password complexity requirements insufficient",
                recommendation="Require uppercase, lowercase, numbers, and special characters",
                affected_component="password_policy",
                cvss_score=4.0,
            ))

        lockout = policy.get("lockout_threshold", 0)
        if lockout == 0:
            findings.append(AuthFinding(
                finding_id=f"pwd_policy_lockout_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="password_policy",
                description="No account lockout policy configured",
                recommendation="Implement account lockout after 5 failed attempts",
                affected_component="password_policy",
                cvss_score=5.0,
            ))

        return assessment

    async def _review_session_management(
        self,
        auth_config: dict[str, Any],
        findings: list[AuthFinding],
    ) -> dict[str, Any]:
        """Review session management configuration."""
        session = auth_config.get("session_management", {})

        assessment = {
            "timeout_seconds": session.get("timeout_seconds", 0),
            "secure_cookies": session.get("secure_cookies", False),
            "httponly_cookies": session.get("httponly_cookies", False),
            "samesite": session.get("samesite", ""),
            "session_regeneration": session.get("regenerate_on_login", False),
        }

        timeout = session.get("timeout_seconds", 0)
        if timeout == 0 or timeout > 3600:
            findings.append(AuthFinding(
                finding_id=f"session_timeout_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="session_management",
                description=f"Session timeout too long or not set: {timeout}s",
                recommendation="Set session timeout to 15-30 minutes for sensitive applications",
                affected_component="session_management",
                cvss_score=4.5,
            ))

        if not session.get("secure_cookies", False):
            findings.append(AuthFinding(
                finding_id=f"session_cookie_secure_{secrets.token_hex(4)}",
                severity=SeverityLevel.HIGH,
                category="session_management",
                description="Session cookies not marked as Secure",
                recommendation="Enable Secure flag on all session cookies",
                affected_component="session_management",
                cvss_score=5.5,
            ))

        if not session.get("httponly_cookies", False):
            findings.append(AuthFinding(
                finding_id=f"session_cookie_httponly_{secrets.token_hex(4)}",
                severity=SeverityLevel.HIGH,
                category="session_management",
                description="Session cookies not marked as HttpOnly",
                recommendation="Enable HttpOnly flag to prevent XSS cookie theft",
                affected_component="session_management",
                cvss_score=5.5,
            ))

        samesite = session.get("samesite", "")
        if samesite.lower() not in ["strict", "lax"]:
            findings.append(AuthFinding(
                finding_id=f"session_cookie_samesite_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="session_management",
                description=f"SameSite cookie attribute not properly set: {samesite}",
                recommendation="Set SameSite=Strict or SameSite=Lax",
                affected_component="session_management",
                cvss_score=4.0,
            ))

        return assessment

    async def _review_mfa_config(
        self,
        auth_config: dict[str, Any],
        findings: list[AuthFinding],
    ) -> dict[str, Any]:
        """Review MFA configuration."""
        mfa = auth_config.get("mfa", {})

        assessment = {
            "enabled": mfa.get("enabled", False),
            "methods": mfa.get("methods", []),
            "required_for_admin": mfa.get("required_for_admin", False),
            "backup_codes": mfa.get("backup_codes", False),
        }

        if not mfa.get("enabled", False):
            findings.append(AuthFinding(
                finding_id=f"mfa_not_enabled_{secrets.token_hex(4)}",
                severity=SeverityLevel.HIGH,
                category="mfa",
                description="Multi-factor authentication not enabled",
                recommendation="Enable MFA for all users, required for admins",
                affected_component="authentication",
                cvss_score=7.0,
            ))

        if not mfa.get("required_for_admin", False):
            findings.append(AuthFinding(
                finding_id=f"mfa_admin_required_{secrets.token_hex(4)}",
                severity=SeverityLevel.HIGH,
                category="mfa",
                description="MFA not required for administrative accounts",
                recommendation="Require MFA for all administrative access",
                affected_component="authentication",
                cvss_score=7.5,
            ))

        methods = mfa.get("methods", [])
        if "SMS" in methods and len(methods) == 1:
            findings.append(AuthFinding(
                finding_id=f"mfa_sms_only_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="mfa",
                description="SMS-only MFA is vulnerable to SIM swapping",
                recommendation="Offer TOTP, WebAuthn, or hardware tokens",
                affected_component="authentication",
                cvss_score=4.5,
            ))

        return assessment

    async def _review_token_handling(
        self,
        auth_config: dict[str, Any],
        findings: list[AuthFinding],
    ) -> dict[str, Any]:
        """Review token handling security."""
        tokens = auth_config.get("tokens", {})

        assessment = {
            "type": tokens.get("type", "unknown"),
            "expiry_seconds": tokens.get("expiry_seconds", 0),
            "refresh_enabled": tokens.get("refresh_enabled", False),
            "secure_storage": tokens.get("secure_storage", False),
        }

        token_type = tokens.get("type", "").upper()
        if "JWT" in token_type:
            algorithm = tokens.get("algorithm", "")
            if algorithm.upper() in ["NONE", "HS256"]:
                findings.append(AuthFinding(
                    finding_id=f"token_jwt_weak_{secrets.token_hex(4)}",
                    severity=SeverityLevel.HIGH,
                    category="tokens",
                    description=f"Weak JWT algorithm: {algorithm}",
                    recommendation="Use RS256 or ES256 for JWT signing",
                    affected_component="token_handler",
                    cvss_score=6.5,
                ))

        expiry = tokens.get("expiry_seconds", 0)
        if expiry == 0 or expiry > 3600:
            findings.append(AuthFinding(
                finding_id=f"token_expiry_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="tokens",
                description=f"Token expiry too long or not set: {expiry}s",
                recommendation="Set token expiry to 15-60 minutes with refresh tokens",
                affected_component="token_handler",
                cvss_score=4.5,
            ))

        if not tokens.get("secure_storage", False):
            findings.append(AuthFinding(
                finding_id=f"token_storage_{secrets.token_hex(4)}",
                severity=SeverityLevel.MEDIUM,
                category="tokens",
                description="Tokens not stored securely",
                recommendation="Store tokens in secure, httpOnly cookies or secure storage",
                affected_component="token_handler",
                cvss_score=5.0,
            ))

        return assessment

    def _calculate_auth_score(self, findings: list[AuthFinding]) -> float:
        """Calculate authentication security score."""
        score = 100.0

        severity_penalties = {
            SeverityLevel.CRITICAL: 25.0,
            SeverityLevel.HIGH: 15.0,
            SeverityLevel.MEDIUM: 8.0,
            SeverityLevel.LOW: 3.0,
            SeverityLevel.INFO: 1.0,
        }

        for finding in findings:
            score -= severity_penalties.get(finding.severity, 0)

        return max(0.0, min(100.0, score))

    def _map_auth_compliance(self, findings: list[AuthFinding]) -> dict[str, Any]:
        """Map findings to compliance standards."""
        compliance = {
            "OWASP_Top10": {"violations": 0, "status": "compliant"},
            "NIST_800_63B": {"violations": 0, "status": "compliant"},
            "PCI_DSS": {"violations": 0, "status": "compliant"},
        }

        for finding in findings:
            for violation in finding.compliance_violations if hasattr(finding, "compliance_violations") else []:
                if "OWASP" in violation:
                    compliance["OWASP_Top10"]["violations"] += 1
                if "NIST" in violation:
                    compliance["NIST_800_63B"]["violations"] += 1
                if "PCI" in violation:
                    compliance["PCI_DSS"]["violations"] += 1

        for standard in compliance:
            if compliance[standard]["violations"] > 0:
                compliance[standard]["status"] = "non-compliant"

        return compliance

    async def _generate_os_hardening(
        self,
        system_type: str,
        findings: list[HardeningFinding],
    ) -> None:
        """Generate OS hardening recommendations."""
        findings.append(HardeningFinding(
            finding_id=f"os_updates_{secrets.token_hex(4)}",
            severity=SeverityLevel.HIGH,
            category="operating_system",
            description="Automated security updates not verified",
            current_state="unknown",
            recommended_state="Automated security patching enabled",
            remediation_steps=[
                "Enable automatic security updates",
                "Configure unattended-upgrades or equivalent",
                "Test patches in staging before production",
                "Maintain update logs for compliance",
            ],
            references=[
                "https://owasp.org/www-project-cheat-sheet-series/",
                "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism",
            ],
        ))

        findings.append(HardeningFinding(
            finding_id=f"os_services_{secrets.token_hex(4)}",
            severity=SeverityLevel.MEDIUM,
            category="operating_system",
            description="Unnecessary services may be running",
            current_state="all_services_enabled",
            recommended_state="Minimal service footprint",
            remediation_steps=[
                "Audit running services",
                "Disable unused services",
                "Remove unnecessary software",
                "Document required services",
            ],
            references=["https://www.cisecurity.org/benchmark"],
        ))

    async def _generate_network_hardening(
        self,
        system_type: str,
        findings: list[HardeningFinding],
    ) -> None:
        """Generate network hardening recommendations."""
        findings.append(HardeningFinding(
            finding_id=f"net_firewall_{secrets.token_hex(4)}",
            severity=SeverityLevel.HIGH,
            category="network_security",
            description="Firewall configuration not verified",
            current_state="unknown",
            recommended_state="Default-deny firewall policy",
            remediation_steps=[
                "Implement default-deny firewall rules",
                "Allow only required ports and protocols",
                "Enable firewall logging",
                "Review rules quarterly",
            ],
            references=[
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "https://www.cisecurity.org/controls",
            ],
        ))

        findings.append(HardeningFinding(
            finding_id=f"net_tls_{secrets.token_hex(4)}",
            severity=SeverityLevel.HIGH,
            category="network_security",
            description="TLS configuration requires validation",
            current_state="unknown",
            recommended_state="TLS 1.3 with strong ciphers only",
            remediation_steps=[
                "Disable TLS 1.0 and 1.1",
                "Enable TLS 1.3",
                "Use strong cipher suites only",
                "Enable HSTS",
                "Implement certificate pinning for mobile apps",
            ],
            references=["https://owasp.org/www-project-secure-transport-layer-configuration-cheat-sheet/"],
        ))

    async def _generate_application_hardening(
        self,
        system_type: str,
        findings: list[HardeningFinding],
    ) -> None:
        """Generate application hardening recommendations."""
        findings.append(HardeningFinding(
            finding_id=f"app_headers_{secrets.token_hex(4)}",
            severity=SeverityLevel.MEDIUM,
            category="application_security",
            description="Security headers not verified",
            current_state="unknown",
            recommended_state="All security headers configured",
            remediation_steps=[
                "Set Content-Security-Policy header",
                "Enable X-Frame-Options: DENY",
                "Set X-Content-Type-Options: nosniff",
                "Configure Strict-Transport-Security",
                "Set Referrer-Policy header",
            ],
            references=["https://owasp.org/www-project-secure-headers/"],
        ))

        findings.append(HardeningFinding(
            finding_id=f"app_deps_{secrets.token_hex(4)}",
            severity=SeverityLevel.HIGH,
            category="application_security",
            description="Dependency vulnerability scanning not verified",
            current_state="unknown",
            recommended_state="Automated dependency scanning enabled",
            remediation_steps=[
                "Enable SCA (Software Composition Analysis)",
                "Configure automated vulnerability scanning",
                "Set up dependency update alerts",
                "Remove unused dependencies",
            ],
            references=[
                "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                "https://github.com/dependency-check/DependencyCheck",
            ],
        ))

    async def _generate_access_hardening(
        self,
        system_type: str,
        findings: list[HardeningFinding],
    ) -> None:
        """Generate access control hardening recommendations."""
        findings.append(HardeningFinding(
            finding_id=f"access_mfa_{secrets.token_hex(4)}",
            severity=SeverityLevel.HIGH,
            category="access_control",
            description="MFA enforcement not verified",
            current_state="unknown",
            recommended_state="MFA required for all users",
            remediation_steps=[
                "Enable MFA for all user accounts",
                "Require MFA for privileged access",
                "Use phishing-resistant MFA (WebAuthn)",
                "Implement backup codes securely",
            ],
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://pages.nist.gov/800-63-3/sp800-63b.html",
            ],
        ))

        findings.append(HardeningFinding(
            finding_id=f"access_rbac_{secrets.token_hex(4)}",
            severity=SeverityLevel.MEDIUM,
            category="access_control",
            description="Role-based access control not verified",
            current_state="unknown",
            recommended_state="Least privilege RBAC implemented",
            remediation_steps=[
                "Implement role-based access control",
                "Apply principle of least privilege",
                "Review permissions quarterly",
                "Remove orphaned accounts",
            ],
            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        ))

    async def _generate_logging_hardening(
        self,
        system_type: str,
        findings: list[HardeningFinding],
    ) -> None:
        """Generate logging and monitoring hardening recommendations."""
        findings.append(HardeningFinding(
            finding_id=f"log_audit_{secrets.token_hex(4)}",
            severity=SeverityLevel.MEDIUM,
            category="logging_monitoring",
            description="Audit logging configuration not verified",
            current_state="unknown",
            recommended_state="Comprehensive audit logging enabled",
            remediation_steps=[
                "Enable authentication logging",
                "Log authorization failures",
                "Log data access and modifications",
                "Protect log integrity",
                "Set up log retention policy",
            ],
            references=[
                "https://owasp.org/www-project-cheat-sheet-series/cheatsheets/Logging_Cheat_Sheet.html",
                "https://www.cisecurity.org/controls/audit-log-management",
            ],
        ))

        findings.append(HardeningFinding(
            finding_id=f"log_alerting_{secrets.token_hex(4)}",
            severity=SeverityLevel.MEDIUM,
            category="logging_monitoring",
            description="Security alerting not configured",
            current_state="unknown",
            recommended_state="Real-time security alerting enabled",
            remediation_steps=[
                "Configure alerts for failed logins",
                "Alert on privilege escalation",
                "Monitor for anomalous behavior",
                "Integrate with SIEM",
            ],
            references=["https://owasp.org/www-project-top-10-cloud-security-risks/"],
        ))

    def _calculate_hardening_score(self, findings: list[HardeningFinding]) -> float:
        """Calculate overall hardening score."""
        score = 100.0

        severity_penalties = {
            SeverityLevel.CRITICAL: 20.0,
            SeverityLevel.HIGH: 12.0,
            SeverityLevel.MEDIUM: 6.0,
            SeverityLevel.LOW: 2.0,
            SeverityLevel.INFO: 1.0,
        }

        for finding in findings:
            score -= severity_penalties.get(finding.severity, 0)

        return max(0.0, min(100.0, score))

    def _prioritize_recommendations(
        self,
        findings: list[HardeningFinding],
    ) -> list[dict[str, Any]]:
        """Prioritize recommendations by severity and impact."""
        recommendations = []

        priority_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }

        sorted_findings = sorted(findings, key=lambda f: priority_order.get(f.severity, 5))

        for idx, finding in enumerate(sorted_findings):
            recommendations.append({
                "priority": idx + 1,
                "severity": finding.severity.value,
                "category": finding.category,
                "description": finding.description,
                "remediation_steps": finding.remediation_steps,
                "references": finding.references,
            })

        return recommendations

    def _calculate_compliance_scores(
        self,
        findings: list[HardeningFinding],
    ) -> dict[str, float]:
        """Calculate compliance framework scores."""
        frameworks = {
            "OWASP_Top10": {"total": 10, "addressed": 0},
            "CIS_Controls": {"total": 18, "addressed": 0},
            "NIST_800_53": {"total": 20, "addressed": 0},
        }

        for finding in findings:
            if "OWASP" in str(finding.references):
                frameworks["OWASP_Top10"]["addressed"] += 1
            if "CIS" in str(finding.references):
                frameworks["CIS_Controls"]["addressed"] += 1
            if "NIST" in str(finding.references):
                frameworks["NIST_800_53"]["addressed"] += 1

        return {
            fw: min(100.0, (data["addressed"] / data["total"]) * 100)
            for fw, data in frameworks.items()
        }

    def _determine_risk_level(
        self,
        findings: list[HardeningFinding],
        overall_score: float,
    ) -> SeverityLevel:
        """Determine overall risk level."""
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)

        if critical_count > 0 or overall_score < 40:
            return SeverityLevel.CRITICAL
        elif high_count > 2 or overall_score < 60:
            return SeverityLevel.HIGH
        elif overall_score < 80:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _generate_executive_summary(
        self,
        system_type: str,
        overall_score: float,
        risk_level: SeverityLevel,
        finding_count: int,
    ) -> str:
        """Generate executive summary for hardening report."""
        risk_descriptions = {
            SeverityLevel.CRITICAL: "Critical security gaps require immediate attention",
            SeverityLevel.HIGH: "Significant security improvements needed",
            SeverityLevel.MEDIUM: "Moderate security enhancements recommended",
            SeverityLevel.LOW: "Minor security optimizations suggested",
            SeverityLevel.INFO: "Security posture is strong",
        }

        return (
            f"Security hardening assessment for {system_type} systems. "
            f"Overall security score: {overall_score:.0f}/100. "
            f"Risk level: {risk_level.value.upper()}. "
            f"Identified {finding_count} findings requiring attention. "
            f"{risk_descriptions.get(risk_level, '')} "
            f"Prioritize remediation of CRITICAL and HIGH severity findings first."
        )

    async def _probe_tls(
        self,
        hostname: str,
        port: int,
    ) -> tuple[str, str, Optional[CertificateInfo], bool]:
        """Probe TLS connection and extract information."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        loop = asyncio.get_event_loop()

        def _connect() -> tuple[str, str, Optional[CertificateInfo], bool]:
            try:
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        version = ssock.version()
                        cipher = ssock.cipher()
                        cert = ssock.getpeercert()

                        cert_info = None
                        if cert:
                            not_after = cert.get("notAfter", "")
                            not_before = cert.get("notBefore", "")
                            subject = str(cert.get("subject", []))
                            issuer = str(cert.get("issuer", []))

                            valid_to = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            valid_from = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                            days_until_expiry = (valid_to - datetime.now(timezone.utc)).days

                            san_raw = cert.get("subjectAltName", [])
                            san = [f"{typ}:{val}" for typ, val in san_raw]

                            cert_info = CertificateInfo(
                                subject=subject,
                                issuer=issuer,
                                valid_from=valid_from,
                                valid_to=valid_to,
                                serial_number=cert.get("serialNumber", ""),
                                signature_algorithm=cert.get("signatureAlgorithm", ""),
                                key_size=0,
                                san=san,
                                is_self_signed=subject == issuer,
                                days_until_expiry=days_until_expiry,
                            )

                        tls_version = version.split()[1] if version else ""
                        cipher_name = cipher[0] if cipher else ""
                        chain_valid = True

                        return tls_version, cipher_name, cert_info, chain_valid

            except ssl.SSLError as e:
                raise e
            except Exception as e:
                raise e

        return await loop.run_in_executor(None, _connect)

    async def _check_protocol_vulnerabilities(
        self,
        hostname: str,
        port: int,
        vulnerabilities: list[str],
    ) -> None:
        """Check for protocol vulnerabilities."""
        vulnerable_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

        for protocol in vulnerable_protocols:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                if protocol == "SSLv2":
                    continue
                elif protocol == "SSLv3":
                    context.options |= ssl.OP_NO_SSLv2
                    context.options |= ssl.OP_NO_TLSv1
                    context.options |= ssl.OP_NO_TLSv1_1
                    context.options |= ssl.OP_NO_TLSv1_2
                elif protocol == "TLSv1.0":
                    context.options |= ssl.OP_NO_SSLv2
                    context.options |= ssl.OP_NO_SSLv3
                    context.options |= ssl.OP_NO_TLSv1_1
                    context.options |= ssl.OP_NO_TLSv1_2
                    context.options |= ssl.OP_NO_TLSv1_3
                elif protocol == "TLSv1.1":
                    context.options |= ssl.OP_NO_SSLv2
                    context.options |= ssl.OP_NO_SSLv3
                    context.options |= ssl.OP_NO_TLSv1
                    context.options |= ssl.OP_NO_TLSv1_2
                    context.options |= ssl.OP_NO_TLSv1_3

                loop = asyncio.get_event_loop()

                def _try_connect() -> bool:
                    try:
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                return True
                    except Exception:
                        return False

                connected = await loop.run_in_executor(None, _try_connect)
                if connected:
                    vulnerabilities.append(f"Supports deprecated protocol: {protocol}")

            except Exception:
                pass

    def _evaluate_tls_version(self, version: str) -> float:
        """Evaluate TLS version security."""
        version_scores = {
            "TLSv1.3": 100.0,
            "TLSv1.2": 85.0,
            "TLSv1.1": 40.0,
            "TLSv1.0": 30.0,
            "SSLv3": 10.0,
            "SSLv2": 0.0,
        }

        return version_scores.get(version, 0.0)

    def _evaluate_cipher_suite(self, cipher_suite: str) -> float:
        """Evaluate cipher suite security."""
        cipher_upper = cipher_suite.upper()

        weak_indicators = ["RC4", "DES", "3DES", "MD5", "NULL", "ANON", "EXPORT"]
        strong_indicators = ["GCM", "CHACHA20", "POLY1305"]

        if any(weak in cipher_upper for weak in weak_indicators):
            return 30.0

        if any(strong in cipher_upper for strong in strong_indicators):
            if "SHA256" in cipher_upper or "SHA384" in cipher_upper:
                return 95.0
            return 85.0

        return 70.0

    def _evaluate_certificate(self, cert_info: CertificateInfo) -> float:
        """Evaluate certificate security."""
        score = 100.0

        if cert_info.is_self_signed:
            score -= 30.0

        if cert_info.key_size < 2048:
            score -= 25.0
        elif cert_info.key_size < 4096:
            score -= 5.0

        if "SHA1" in cert_info.signature_algorithm.upper():
            score -= 20.0

        if "MD5" in cert_info.signature_algorithm.upper():
            score -= 40.0

        if cert_info.days_until_expiry < 7:
            score -= 30.0
        elif cert_info.days_until_expiry < 30:
            score -= 15.0

        return max(0.0, score)

    async def _check_security_headers(
        self,
        hostname: str,
        port: int,
    ) -> dict[str, Any]:
        """Check security headers (simplified - would need HTTP request in production)."""
        return {
            "strict_transport_security": False,
            "content_security_policy": False,
            "x_frame_options": False,
            "x_content_type_options": False,
            "referrer_policy": False,
            "permissions_policy": False,
        }

    def _crypto_result_to_dict(self, result: CryptoAuditResult) -> dict[str, Any]:
        """Convert CryptoAuditResult to dictionary."""
        return {
            "audit_id": result.audit_id,
            "timestamp": result.timestamp.isoformat(),
            "passed": result.passed,
            "score": result.score,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "affected_component": f.affected_component,
                    "compliance_violations": f.compliance_violations,
                }
                for f in result.findings
            ],
            "compliant_algorithms": result.compliant_algorithms,
            "deprecated_algorithms": result.deprecated_algorithms,
            "key_strength_assessment": result.key_strength_assessment,
            "random_quality": result.random_quality,
            "recommendations": result.recommendations,
        }

    def _auth_result_to_dict(self, result: AuthReviewResult) -> dict[str, Any]:
        """Convert AuthReviewResult to dictionary."""
        return {
            "review_id": result.review_id,
            "timestamp": result.timestamp.isoformat(),
            "passed": result.passed,
            "score": result.score,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "category": f.category,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "affected_component": f.affected_component,
                    "cvss_score": f.cvss_score,
                }
                for f in result.findings
            ],
            "password_policy_assessment": result.password_policy_assessment,
            "session_management_assessment": result.session_management_assessment,
            "mfa_status": result.mfa_status,
            "token_security": result.token_security,
            "compliance_mapping": result.compliance_mapping,
        }

    def _hardening_report_to_dict(self, report: HardeningReport) -> dict[str, Any]:
        """Convert HardeningReport to dictionary."""
        return {
            "report_id": report.report_id,
            "timestamp": report.timestamp.isoformat(),
            "system_type": report.system_type,
            "overall_score": report.overall_score,
            "risk_level": report.risk_level.value,
            "executive_summary": report.executive_summary,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "category": f.category,
                    "description": f.description,
                    "current_state": f.current_state,
                    "recommended_state": f.recommended_state,
                    "remediation_steps": f.remediation_steps,
                    "references": f.references,
                }
                for f in report.findings
            ],
            "recommendations": report.recommendations,
            "compliance_score": report.compliance_score,
        }

    def _tls_result_to_dict(self, result: TLSValidationResult) -> dict[str, Any]:
        """Convert TLSValidationResult to dictionary."""
        return {
            "validation_id": result.validation_id,
            "timestamp": result.timestamp.isoformat(),
            "hostname": result.hostname,
            "passed": result.passed,
            "score": result.score,
            "tls_version": result.tls_version,
            "cipher_suite": result.cipher_suite,
            "chain_valid": result.chain_valid,
            "protocol_vulnerabilities": result.protocol_vulnerabilities,
            "supported_versions": result.supported_versions,
            "supported_ciphers": result.supported_ciphers,
            "security_headers": result.security_headers,
            "recommendations": result.recommendations,
            "certificate": {
                "subject": result.certificate.subject,
                "issuer": result.certificate.issuer,
                "valid_from": result.certificate.valid_from.isoformat(),
                "valid_to": result.certificate.valid_to.isoformat(),
                "serial_number": result.certificate.serial_number,
                "signature_algorithm": result.certificate.signature_algorithm,
                "key_size": result.certificate.key_size,
                "san": result.certificate.san,
                "is_self_signed": result.certificate.is_self_signed,
                "days_until_expiry": result.certificate.days_until_expiry,
            }
            if result.certificate
            else None,
        }

    def get_audit_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent audit history."""
        return [self._crypto_result_to_dict(a) for a in self._audit_history[-limit:]]

    def get_review_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent review history."""
        return [self._auth_result_to_dict(r) for r in self._review_history[-limit:]]

    def get_validation_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent validation history."""
        return [self._tls_result_to_dict(v) for v in self._validation_history[-limit:]]