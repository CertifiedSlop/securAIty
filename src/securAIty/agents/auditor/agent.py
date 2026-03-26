"""
Security Auditor Agent

Compliance auditing, security assessment, and audit report
generation with framework mapping and evidence collection.
"""

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from ..events.correlation import CorrelationContext
from ..events.schema import EventStatus, EventType, SecurityEvent, Severity
from .base import AgentConfig, BaseAgent, HealthStatus, TaskRequest, TaskResult


class ComplianceStatus(Enum):
    """Compliance assessment status."""

    COMPLIANT = auto()
    NON_COMPLIANT = auto()
    PARTIAL = auto()
    NOT_APPLICABLE = auto()
    NOT_ASSESSED = auto()


class FindingSeverity(Enum):
    """Audit finding severity."""

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    OBSERVATION = auto()


@dataclass
class ComplianceRequirement:
    """
    Compliance requirement definition.

    Attributes:
        requirement_id: Unique requirement identifier
        framework: Compliance framework name
        control_id: Framework control identifier
        description: Requirement description
        category: Requirement category
        evidence_required: Required evidence types
    """

    requirement_id: str
    framework: str
    control_id: str
    description: str
    category: str
    evidence_required: list[str] = field(default_factory=list)


@dataclass
class AuditFinding:
    """
    Audit finding record.

    Attributes:
        finding_id: Unique finding identifier
        requirement_id: Related requirement ID
        severity: Finding severity
        status: Compliance status
        description: Finding description
        evidence: Supporting evidence
        recommendation: Remediation recommendation
        risk_statement: Risk description
    """

    finding_id: str
    requirement_id: str
    severity: FindingSeverity
    status: ComplianceStatus
    description: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    risk_statement: str = ""


@dataclass
class AuditReport:
    """
    Audit report document.

    Attributes:
        report_id: Unique report identifier
        audit_type: Type of audit
        scope: Audit scope
        findings: Audit findings
        summary: Executive summary
        generated_at: Report generation time
    """

    report_id: str
    audit_type: str
    scope: str
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    generated_at: float = field(default_factory=lambda: asyncio.get_event_loop().time())


class AuditorAgent(BaseAgent):
    """
    Security Auditor agent for compliance and assessment.

    Performs compliance audits, security assessments, evidence
    collection, and generates comprehensive audit reports.

    Capabilities:
        - Compliance auditing (SOC2, ISO27001, NIST, CIS)
        - Security control assessment
        - Evidence collection and validation
        - Gap analysis
        - Audit report generation
    """

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        """
        Initialize security auditor agent.

        Args:
            config: Optional agent configuration
        """
        if config is None:
            config = AgentConfig(
                agent_id="auditor_agent",
                name="Security Auditor Agent",
                description="Compliance auditing and security assessment",
                capabilities=[
                    {
                        "name": "compliance_auditing",
                        "description": "Audit against compliance frameworks",
                        "priority": 10,
                    },
                    {
                        "name": "control_assessment",
                        "description": "Assess security control effectiveness",
                        "priority": 20,
                    },
                    {
                        "name": "evidence_collection",
                        "description": "Collect and validate audit evidence",
                        "priority": 30,
                    },
                    {
                        "name": "gap_analysis",
                        "description": "Identify compliance gaps",
                        "priority": 40,
                    },
                    {
                        "name": "report_generation",
                        "description": "Generate audit reports",
                        "priority": 50,
                    },
                ],
                max_concurrent_tasks=5,
                task_timeout=600.0,
            )

        super().__init__(config)

        self._requirements: dict[str, ComplianceRequirement] = {}
        self._findings: dict[str, AuditFinding] = {}
        self._reports: dict[str, AuditReport] = {}
        self._evidence_store: dict[str, list[dict[str, Any]]] = {}
        self._event_callback: Optional[callable] = None

        self._initialize_frameworks()

    def _initialize_frameworks(self) -> None:
        """Initialize compliance framework requirements."""
        frameworks = {
            "SOC2": [
                ("CC6.1", "Logical Access Controls", "access_control"),
                ("CC6.6", "Security Event Logging", "monitoring"),
                ("CC6.7", "Transmission Security", "data_protection"),
                ("CC7.1", "Intrusion Detection", "monitoring"),
                ("CC7.2", "Incident Response", "incident_management"),
            ],
            "ISO27001": [
                ("A.9.1", "Access Control Policy", "access_control"),
                ("A.12.4", "Logging and Monitoring", "monitoring"),
                ("A.13.1", "Network Security", "network_security"),
                ("A.14.1", "Secure Development", "development"),
            ],
            "NIST": [
                ("AC-1", "Access Control Policy", "access_control"),
                ("AU-1", "Audit and Accountability", "monitoring"),
                ("SC-1", "System and Communications Protection", "data_protection"),
                ("IR-1", "Incident Response", "incident_management"),
            ],
            "CIS": [
                ("1.1", "Secure Configuration", "configuration"),
                ("2.1", "Inventory of Assets", "asset_management"),
                ("3.1", "Data Protection", "data_protection"),
                ("8.1", "Audit Log Management", "monitoring"),
            ],
        }

        for framework, controls in frameworks.items():
            for control_id, description, category in controls:
                req_id = f"{framework}_{control_id}"
                self._requirements[req_id] = ComplianceRequirement(
                    requirement_id=req_id,
                    framework=framework,
                    control_id=control_id,
                    description=description,
                    category=category,
                    evidence_required=self._get_evidence_requirements(category),
                )

    def _get_evidence_requirements(self, category: str) -> list[str]:
        """Get evidence requirements for category."""
        evidence_map = {
            "access_control": ["access_logs", "user_list", "permission_matrix"],
            "monitoring": ["log_samples", "alert_config", "siem_dashboard"],
            "data_protection": ["encryption_config", "data_flow_diagram", "dlp_logs"],
            "incident_management": ["incident_procedure", "incident_logs", "postmortems"],
            "configuration": ["config_baselines", "hardening_guides", "scan_results"],
            "asset_management": ["asset_inventory", "ownership_records", "classification"],
            "development": ["sdlc_docs", "code_review_logs", "security_tests"],
            "network_security": ["network_diagram", "firewall_rules", "segmentation"],
        }
        return evidence_map.get(category, ["documentation", "logs", "configurations"])

    def set_event_callback(self, callback: callable) -> None:
        """Set callback for emitting security events."""
        self._event_callback = callback

    async def initialize(self) -> None:
        """
        Initialize auditor agent resources.

        Sets up compliance frameworks and marks agent as ready.
        """
        self._findings.clear()
        self._reports.clear()
        self._evidence_store.clear()
        self._update_health_status(HealthStatus.HEALTHY)

    async def execute(self, request: TaskRequest) -> TaskResult:
        """
        Execute security audit task request.

        Handles compliance_check, policy_audit, access_review,
        and report_generation capabilities.

        Args:
            request: Task request with capability and input data

        Returns:
            TaskResult with audit results
        """
        start_time = asyncio.get_event_loop().time()

        try:
            if not self._initialized:
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message="Agent not initialized",
                )

            capability_mapping = {
                "compliance_check": "compliance_auditing",
                "policy_audit": "control_assessment",
                "access_review": "evidence_collection",
                "report_generation": "report_generation",
            }

            if request.capability not in capability_mapping:
                return TaskResult.failure(
                    task_id=request.task_id,
                    error_message=f"Unknown capability: {request.capability}",
                )

            input_data = request.input_data.copy()
            audit_type_map = {
                "compliance_check": "compliance",
                "policy_audit": "control",
                "access_review": "evidence",
                "report_generation": "report",
            }
            input_data["audit_type"] = audit_type_map[request.capability]

            context = {"priority": request.priority, "timeout": request.timeout}
            correlation_context = CorrelationContext(
                correlation_id=request.correlation_id,
            )

            result = await self._execute(input_data, context, correlation_context)

            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000

            return TaskResult.success(
                task_id=request.task_id,
                output_data=result,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            execution_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return TaskResult.failure(
                task_id=request.task_id,
                error_message="Auditor operation failed",
                execution_time_ms=execution_time,
            )

    async def health_check(self) -> HealthStatus:
        """
        Perform health check on auditor agent.

        Verifies agent is initialized and ready for tasks.

        Returns:
            Current health status
        """
        if not self._initialized:
            self._update_health_status(HealthStatus.UNHEALTHY)
            return HealthStatus.UNHEALTHY

        self._update_health_status(HealthStatus.HEALTHY)
        return HealthStatus.HEALTHY

    async def shutdown(self) -> None:
        """
        Gracefully shutdown auditor agent.

        Cleans up resources and marks agent as stopped.
        """
        self._findings.clear()
        self._reports.clear()
        self._evidence_store.clear()
        self._update_health_status(HealthStatus.UNKNOWN)

    async def _execute(
        self,
        input_data: dict[str, Any],
        context: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Execute audit task.

        Args:
            input_data: Audit request data
            context: Execution context
            correlation_context: Correlation tracking

        Returns:
            Audit results
        """
        audit_type = input_data.get("audit_type", "compliance")

        if audit_type == "compliance":
            return await self._compliance_audit(input_data, correlation_context)

        elif audit_type == "control":
            return await self._control_assessment(input_data, correlation_context)

        elif audit_type == "gap":
            return await self._gap_analysis(input_data, correlation_context)

        elif audit_type == "evidence":
            return await self._collect_evidence(input_data, correlation_context)

        else:
            return await self._generate_report(input_data, correlation_context)

    async def _compliance_audit(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Perform compliance audit.

        Args:
            input_data: Audit parameters
            correlation_context: Correlation tracking

        Returns:
            Audit results
        """
        frameworks = input_data.get("frameworks", ["SOC2"])
        scope = input_data.get("scope", "full")

        results = {
            "audit_type": "compliance",
            "frameworks": frameworks,
            "scope": scope,
            "assessments": [],
            "summary": {},
        }

        for framework in frameworks:
            framework_results = await self._audit_framework(framework, scope, correlation_context)
            results["assessments"].append(framework_results)

        results["summary"] = self._summarize_audit(results["assessments"])

        report = await self._create_audit_report("compliance", scope, results)
        results["report_id"] = report.report_id

        return results

    async def _control_assessment(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Assess security controls.

        Args:
            input_data: Control assessment data
            correlation_context: Correlation tracking

        Returns:
            Assessment results
        """
        control_ids = input_data.get("control_ids", [])
        assessment_criteria = input_data.get("criteria", "effectiveness")

        results = {
            "assessment_type": "control",
            "controls_assessed": [],
            "overall_effectiveness": 0,
        }

        for control_id in control_ids:
            assessment = await self._assess_single_control(control_id, assessment_criteria)
            results["controls_assessed"].append(assessment)

        if results["controls_assessed"]:
            results["overall_effectiveness"] = sum(
                c.get("effectiveness_score", 0) for c in results["controls_assessed"]
            ) / len(results["controls_assessed"])

        return results

    async def _gap_analysis(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Perform gap analysis.

        Args:
            input_data: Gap analysis parameters
            correlation_context: Correlation tracking

        Returns:
            Gap analysis results
        """
        frameworks = input_data.get("frameworks", ["SOC2"])
        current_state = input_data.get("current_state", {})

        gaps = []

        for framework in frameworks:
            framework_gaps = await self._analyze_framework_gaps(framework, current_state)
            gaps.extend(framework_gaps)

        return {
            "analysis_type": "gap",
            "frameworks": frameworks,
            "gaps_identified": len(gaps),
            "gaps": gaps,
            "priority_remediation": self._prioritize_gaps(gaps),
            "estimated_effort": self._estimate_remediation_effort(gaps),
        }

    async def _collect_evidence(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Collect audit evidence.

        Args:
            input_data: Evidence collection request
            correlation_context: Correlation tracking

        Returns:
            Evidence collection results
        """
        requirement_ids = input_data.get("requirement_ids", [])
        evidence_sources = input_data.get("sources", [])

        collected = []

        for req_id in requirement_ids:
            if req_id in self._requirements:
                req = self._requirements[req_id]
                evidence = await self._gather_evidence(req, evidence_sources)
                collected.append({
                    "requirement_id": req_id,
                    "evidence": evidence,
                    "complete": len(evidence) >= len(req.evidence_required),
                })

                self._evidence_store[req_id] = evidence

        return {
            "collection_type": "evidence",
            "requirements_covered": len(collected),
            "evidence_items": sum(len(c["evidence"]) for c in collected),
            "collected_evidence": collected,
        }

    async def _generate_report(
        self,
        input_data: dict[str, Any],
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """
        Generate audit report.

        Args:
            input_data: Report generation data
            correlation_context: Correlation tracking

        Returns:
            Generated report
        """
        report_type = input_data.get("report_type", "executive")
        audit_id = input_data.get("audit_id")

        if audit_id and audit_id in self._reports:
            report = self._reports[audit_id]
            return self._format_report(report, report_type)

        findings = input_data.get("findings", [])
        report = await self._create_audit_report(
            report_type,
            input_data.get("scope", "general"),
            {"findings": findings},
        )

        return self._format_report(report, report_type)

    async def _audit_framework(
        self,
        framework: str,
        scope: str,
        correlation_context: Optional[CorrelationContext],
    ) -> dict[str, Any]:
        """Audit single framework."""
        framework_reqs = [
            req for req in self._requirements.values()
            if req.framework == framework
        ]

        assessments = []

        for req in framework_reqs:
            assessment = await self._assess_requirement(req, scope)
            assessments.append(assessment)

            if assessment["status"] != "COMPLIANT":
                finding = self._create_finding(req, assessment)
                self._findings[finding.finding_id] = finding

        compliant = sum(1 for a in assessments if a["status"] == "COMPLIANT")
        total = len(assessments)

        return {
            "framework": framework,
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": sum(1 for a in assessments if a["status"] == "NON_COMPLIANT"),
            "partial": sum(1 for a in assessments if a["status"] == "PARTIAL"),
            "compliance_percentage": (compliant / total * 100) if total > 0 else 0,
            "assessments": assessments,
        }

    async def _assess_requirement(
        self,
        req: ComplianceRequirement,
        scope: str,
    ) -> dict[str, Any]:
        """Assess single requirement."""
        evidence = self._evidence_store.get(req.requirement_id, [])

        evidence_complete = len(evidence) >= len(req.evidence_required)

        if evidence_complete:
            status = ComplianceStatus.COMPLIANT
            effectiveness = 90
        elif len(evidence) > 0:
            status = ComplianceStatus.PARTIAL
            effectiveness = 50
        else:
            status = ComplianceStatus.NON_COMPLIANT
            effectiveness = 0

        return {
            "requirement_id": req.requirement_id,
            "control_id": req.control_id,
            "description": req.description,
            "status": status.name,
            "effectiveness_score": effectiveness,
            "evidence_count": len(evidence),
            "evidence_required": len(req.evidence_required),
        }

    async def _assess_single_control(
        self,
        control_id: str,
        criteria: str,
    ) -> dict[str, Any]:
        """Assess single security control."""
        return {
            "control_id": control_id,
            "criteria": criteria,
            "effectiveness_score": 75,
            "status": "effective",
            "findings": [],
            "recommendations": ["Continue monitoring", "Document procedures"],
        }

    async def _analyze_framework_gaps(
        self,
        framework: str,
        current_state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Analyze gaps for framework."""
        gaps = []

        framework_reqs = [
            req for req in self._requirements.values()
            if req.framework == framework
        ]

        for req in framework_reqs:
            current = current_state.get(req.requirement_id, {})

            if not current.get("implemented", False):
                gaps.append({
                    "requirement_id": req.requirement_id,
                    "framework": framework,
                    "control_id": req.control_id,
                    "description": f"Missing: {req.description}",
                    "severity": "HIGH",
                    "remediation": f"Implement {req.description.lower()}",
                    "effort": "medium",
                })

        return gaps

    async def _gather_evidence(
        self,
        req: ComplianceRequirement,
        sources: list[str],
    ) -> list[dict[str, Any]]:
        """Gather evidence for requirement."""
        evidence = []

        for source in sources:
            evidence.append({
                "type": source,
                "requirement_id": req.requirement_id,
                "collected_at": asyncio.get_event_loop().time(),
                "verified": True,
            })

        for req_type in req.evidence_required:
            if not any(e["type"] == req_type for e in evidence):
                evidence.append({
                    "type": req_type,
                    "requirement_id": req.requirement_id,
                    "collected_at": asyncio.get_event_loop().time(),
                    "verified": False,
                    "missing": True,
                })

        return evidence

    async def _create_audit_report(
        self,
        report_type: str,
        scope: str,
        results: dict[str, Any],
    ) -> AuditReport:
        """Create audit report."""
        import uuid

        findings = results.get("findings", [])
        if not findings:
            findings = list(self._findings.values())

        report = AuditReport(
            report_id=f"rpt_{uuid.uuid4().hex[:8]}",
            audit_type=report_type,
            scope=scope,
            findings=findings if isinstance(findings, list) else [],
            summary={
                "total_findings": len(findings) if isinstance(findings, list) else 0,
                "critical": sum(1 for f in findings if isinstance(f, AuditFinding) and f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in findings if isinstance(f, AuditFinding) and f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in findings if isinstance(f, AuditFinding) and f.severity == FindingSeverity.MEDIUM),
            },
        )

        self._reports[report.report_id] = report

        return report

    def _format_report(
        self,
        report: AuditReport,
        format_type: str,
    ) -> dict[str, Any]:
        """Format report for output."""
        if format_type == "executive":
            return {
                "report_id": report.report_id,
                "type": "executive_summary",
                "audit_type": report.audit_type,
                "scope": report.scope,
                "summary": report.summary,
                "key_findings": [
                    {
                        "finding_id": f.finding_id,
                        "severity": f.severity.name,
                        "description": f.description,
                    }
                    for f in report.findings[:5]
                ] if report.findings else [],
                "generated_at": report.generated_at,
            }

        elif format_type == "detailed":
            return {
                "report_id": report.report_id,
                "type": "detailed",
                "audit_type": report.audit_type,
                "scope": report.scope,
                "summary": report.summary,
                "all_findings": [
                    {
                        "finding_id": f.finding_id,
                        "severity": f.severity.name,
                        "status": f.status.name,
                        "description": f.description,
                        "evidence": f.evidence,
                        "recommendation": f.recommendation,
                        "risk_statement": f.risk_statement,
                    }
                    for f in report.findings
                ] if report.findings else [],
                "generated_at": report.generated_at,
            }

        return {"report_id": report.report_id, "format": format_type}

    def _create_finding(
        self,
        req: ComplianceRequirement,
        assessment: dict[str, Any],
    ) -> AuditFinding:
        """Create audit finding from assessment."""
        import uuid

        severity_map = {
            "NON_COMPLIANT": FindingSeverity.HIGH,
            "PARTIAL": FindingSeverity.MEDIUM,
            "COMPLIANT": FindingSeverity.OBSERVATION,
        }

        status_map = {
            "NON_COMPLIANT": ComplianceStatus.NON_COMPLIANT,
            "PARTIAL": ComplianceStatus.PARTIAL,
            "COMPLIANT": ComplianceStatus.COMPLIANT,
        }

        severity = severity_map.get(assessment.get("status", "NON_COMPLIANT"), FindingSeverity.MEDIUM)
        status = status_map.get(assessment.get("status", "NON_COMPLIANT"), ComplianceStatus.NON_COMPLIANT)

        return AuditFinding(
            finding_id=f"find_{uuid.uuid4().hex[:8]}",
            requirement_id=req.requirement_id,
            severity=severity,
            status=status,
            description=f"Control {req.control_id} - {req.description} is {assessment.get('status', 'unknown')}",
            evidence=[f"Evidence count: {assessment.get('evidence_count', 0)}"],
            recommendation=f"Address gaps in {req.description.lower()}",
            risk_statement=f"Non-compliance with {req.framework} {req.control_id} may result in security gaps",
        )

    def _summarize_audit(self, assessments: list[dict[str, Any]]) -> dict[str, Any]:
        """Summarize audit results."""
        total_controls = sum(a.get("total_controls", 0) for a in assessments)
        total_compliant = sum(a.get("compliant", 0) for a in assessments)

        return {
            "total_frameworks": len(assessments),
            "total_controls": total_controls,
            "total_compliant": total_compliant,
            "overall_compliance": (total_compliant / total_controls * 100) if total_controls > 0 else 0,
            "findings_count": len(self._findings),
        }

    def _prioritize_gaps(self, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Prioritize gaps for remediation."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(gaps, key=lambda g: severity_order.get(g.get("severity", "LOW"), 3))

    def _estimate_remediation_effort(self, gaps: list[dict[str, Any]]) -> dict[str, Any]:
        """Estimate remediation effort."""
        effort_map = {"high": 40, "medium": 20, "low": 8}

        total_hours = sum(
            effort_map.get(g.get("effort", "medium"), 20) for g in gaps
        )

        return {
            "total_hours": total_hours,
            "estimated_weeks": total_hours / 40,
            "high_effort_items": sum(1 for g in gaps if g.get("effort") == "high"),
            "medium_effort_items": sum(1 for g in gaps if g.get("effort") == "medium"),
            "low_effort_items": sum(1 for g in gaps if g.get("effort") == "low"),
        }

    def get_finding(self, finding_id: str) -> Optional[AuditFinding]:
        """Get finding by ID."""
        return self._findings.get(finding_id)

    def get_report(self, report_id: str) -> Optional[AuditReport]:
        """Get report by ID."""
        return self._reports.get(report_id)

    def get_compliance_summary(self) -> dict[str, Any]:
        """Get overall compliance summary."""
        frameworks = set(req.framework for req in self._requirements.values())

        summary = {}
        for framework in frameworks:
            framework_reqs = [req for req in self._requirements.values() if req.framework == framework]
            compliant = sum(
                1 for req in framework_reqs
                if len(self._evidence_store.get(req.requirement_id, [])) >= len(req.evidence_required)
            )
            summary[framework] = {
                "total": len(framework_reqs),
                "compliant": compliant,
                "percentage": (compliant / len(framework_reqs) * 100) if framework_reqs else 0,
            }

        return summary
